//! Telegram inline buttons (item 82): every certificate alert is posted as a card
//! with "Known", "Suspicious" and "Mute" buttons; presses arrive via `getUpdates`
//! long polling. Only configured user ids in the configured chat are obeyed.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use llcforge_alert::{
    env_secret, Alert as KitAlert, AlertHandle, NewSilence, Severity, SilenceStore,
};
use serde::Deserialize;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::config::TelegramActionsConfig;
use crate::inventory::Inventory;
use crate::notify::{clip, TOOL};

const DEFAULT_API: &str = "https://api.telegram.org";
const MAX_PENDING: usize = 5000;
const MAX_TEXT: usize = 3800;

/// A certificate alert offered to the action chat.
#[derive(Debug, Clone)]
pub struct Card {
    /// Telegram HTML body (already escaped).
    pub text: String,
    /// Inventory key (issuer DN | serial).
    pub key: String,
    pub domain: String,
    pub kind: String,
    pub title: String,
}

#[derive(Clone)]
pub struct TgActions {
    tx: mpsc::Sender<Card>,
}

impl TgActions {
    /// Never blocks; drops the card when the queue is full.
    pub fn offer(&self, card: Card) {
        if self.tx.try_send(card).is_err() {
            tracing::warn!("telegram action queue full, card dropped");
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct Update {
    pub update_id: i64,
    #[serde(default)]
    pub callback_query: Option<CallbackQuery>,
}

#[derive(Debug, Deserialize)]
pub struct CallbackQuery {
    pub id: String,
    pub from: User,
    #[serde(default)]
    pub message: Option<Message>,
    #[serde(default)]
    pub data: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct User {
    pub id: i64,
}

#[derive(Debug, Deserialize)]
pub struct Message {
    pub message_id: i64,
    pub chat: Chat,
}

#[derive(Debug, Deserialize)]
pub struct Chat {
    pub id: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Known,
    Suspicious,
    Mute,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Unauthorized,
    Expired,
    Do(Action, String),
}

/// Callback token: 16 hex characters of SHA-256(inventory key); fits the 64-byte limit.
pub fn token(key: &str) -> String {
    crate::cert::hex(&ring::digest::digest(&ring::digest::SHA256, key.as_bytes()).as_ref()[..8])
}

/// Pure authorisation + parsing of a button press (fail closed).
pub fn decide(
    cfg: &TelegramActionsConfig,
    cb: &CallbackQuery,
    known_token: impl Fn(&str) -> bool,
) -> Decision {
    let chat_ok = cb
        .message
        .as_ref()
        .is_some_and(|m| m.chat.id == cfg.chat_id);
    if !chat_ok || !cfg.allowed_user_ids.contains(&cb.from.id) {
        return Decision::Unauthorized;
    }
    let Some((a, tok)) = cb.data.as_deref().and_then(|d| d.split_once(':')) else {
        return Decision::Expired;
    };
    let action = match a {
        "k" => Action::Known,
        "s" => Action::Suspicious,
        "m" => Action::Mute,
        _ => return Decision::Expired,
    };
    if tok.len() != 16 || !known_token(tok) {
        return Decision::Expired;
    }
    Decision::Do(action, tok.to_string())
}

pub fn keyboard(tok: &str, mute_days: u32) -> serde_json::Value {
    serde_json::json!({ "inline_keyboard": [[
        {"text": "Known", "callback_data": format!("k:{tok}")},
        {"text": "Suspicious", "callback_data": format!("s:{tok}")},
        {"text": format!("Mute {mute_days}d"), "callback_data": format!("m:{tok}")},
    ]]})
}

struct Shared {
    cfg: TelegramActionsConfig,
    client: reqwest::Client,
    base: String,
    pending: Mutex<(HashMap<String, Card>, VecDeque<String>)>,
    handle: AlertHandle,
    inventory: Arc<Mutex<Inventory>>,
    silences: Arc<SilenceStore>,
}

impl Shared {
    fn url(&self, method: &str) -> String {
        format!("{}/{method}", self.base)
    }

    async fn call(
        &self,
        method: &str,
        body: serde_json::Value,
        timeout: Duration,
    ) -> Result<serde_json::Value> {
        let resp = self
            .client
            .post(self.url(method))
            .timeout(timeout)
            .json(&body)
            .send()
            .await
            // without_url: the request URL contains the bot token.
            .map_err(|e| anyhow!("telegram {method} failed: {}", e.without_url()))?;
        let status = resp.status();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| anyhow!("telegram {method} body: {}", e.without_url()))?;
        if bytes.len() > 4 * 1024 * 1024 {
            bail!("telegram {method} response too large");
        }
        let v: serde_json::Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("telegram {method}: invalid JSON"))?;
        if !status.is_success() || v["ok"] != serde_json::Value::Bool(true) {
            let desc: String = v["description"]
                .as_str()
                .unwrap_or("")
                .chars()
                .take(200)
                .collect();
            bail!("telegram {method}: HTTP {status} {desc}");
        }
        Ok(v["result"].clone())
    }

    async fn send_card(&self, card: Card) {
        let tok = token(&card.key);
        let text: String = if card.text.chars().count() > MAX_TEXT {
            // Cut on a line boundary so no HTML tag is split.
            let mut out = String::new();
            for line in card.text.lines() {
                if out.chars().count() + line.chars().count() + 1 > MAX_TEXT {
                    break;
                }
                out.push_str(line);
                out.push('\n');
            }
            out
        } else {
            card.text.clone()
        };
        let body = serde_json::json!({
            "chat_id": self.cfg.chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": true,
            "reply_markup": keyboard(&tok, self.cfg.mute_days),
        });
        match self
            .call("sendMessage", body, Duration::from_secs(15))
            .await
        {
            Ok(_) => {
                if let Ok(mut p) = self.pending.lock() {
                    if p.0.insert(tok.clone(), card).is_none() {
                        p.1.push_back(tok);
                    }
                    while p.1.len() > MAX_PENDING {
                        if let Some(old) = p.1.pop_front() {
                            p.0.remove(&old);
                        }
                    }
                }
            }
            Err(e) => tracing::warn!(error = %format!("{e:#}"), "telegram action card not sent"),
        }
    }

    fn perform(&self, action: Action, card: &Card, user: i64) -> Result<String> {
        let by = format!("telegram:{user}");
        match action {
            Action::Known | Action::Suspicious => {
                let verdict = if action == Action::Known {
                    "known"
                } else {
                    "suspicious"
                };
                if let Ok(mut inv) = self.inventory.lock() {
                    inv.set_verdict(&card.key, verdict, &by);
                }
                if action == Action::Suspicious {
                    self.handle.send(
                        KitAlert::new(
                            TOOL,
                            "cert_suspicious",
                            Severity::Critical,
                            format!("Marked suspicious: {}", clip(&card.title)),
                        )
                        .resource(card.domain.clone())
                        .id(format!("{TOOL}:cert_suspicious:{}", token(&card.key)))
                        .field("marked_by", &by),
                    );
                }
                Ok(format!("Marked {verdict}"))
            }
            Action::Mute => {
                let s = self
                    .silences
                    .add(NewSilence {
                        resource: Some(card.domain.clone()),
                        kind: Some(card.kind.clone()),
                        tool: Some(TOOL.into()),
                        duration: Some(format!("{}d", self.cfg.mute_days)),
                        comment: "muted from Telegram".into(),
                        created_by: Some(by),
                        ..Default::default()
                    })
                    .map_err(|e| anyhow!("{e}"))?;
                Ok(format!(
                    "Muted {} alerts for {} until {}",
                    card.kind,
                    card.domain,
                    s.ends_at.format("%Y-%m-%d %H:%M UTC")
                ))
            }
        }
    }

    async fn on_callback(&self, cb: CallbackQuery) {
        let decision = decide(&self.cfg, &cb, |t| {
            self.pending
                .lock()
                .map(|p| p.0.contains_key(t))
                .unwrap_or(false)
        });
        let reply = match &decision {
            Decision::Unauthorized => {
                tracing::warn!(
                    user = cb.from.id,
                    "telegram button press from an unauthorised user or chat ignored"
                );
                "Not authorised".to_string()
            }
            Decision::Expired => "This card has expired".to_string(),
            Decision::Do(action, tok) => {
                let card = self.pending.lock().ok().and_then(|p| p.0.get(tok).cloned());
                match card.map(|c| self.perform(*action, &c, cb.from.id)) {
                    Some(Ok(msg)) => {
                        tracing::info!(user = cb.from.id, action = ?action, "telegram action applied");
                        if let Some(m) = &cb.message {
                            let label = format!("{msg} (by {})", cb.from.id);
                            let body = serde_json::json!({
                                "chat_id": m.chat.id,
                                "message_id": m.message_id,
                                "reply_markup": {"inline_keyboard": [[{"text": label, "callback_data": "done"}]]},
                            });
                            if let Err(e) = self
                                .call("editMessageReplyMarkup", body, Duration::from_secs(15))
                                .await
                            {
                                tracing::debug!(error = %format!("{e:#}"), "cannot update buttons");
                            }
                        }
                        msg
                    }
                    Some(Err(e)) => format!("Failed: {e:#}"),
                    None => "This card has expired".to_string(),
                }
            }
        };
        let body = serde_json::json!({"callback_query_id": cb.id, "text": reply.chars().take(190).collect::<String>()});
        if let Err(e) = self
            .call("answerCallbackQuery", body, Duration::from_secs(15))
            .await
        {
            tracing::debug!(error = %format!("{e:#}"), "answerCallbackQuery failed");
        }
    }

    async fn poll(self: Arc<Self>) {
        let mut offset: i64 = 0;
        let mut failures = 0u32;
        loop {
            let body = serde_json::json!({
                "offset": offset,
                "timeout": 25,
                "allowed_updates": ["callback_query"],
            });
            match self.call("getUpdates", body, Duration::from_secs(40)).await {
                Ok(v) => {
                    failures = 0;
                    let updates: Vec<Update> = serde_json::from_value(v).unwrap_or_default();
                    for u in updates.into_iter().take(100) {
                        offset = offset.max(u.update_id + 1);
                        if let Some(cb) = u.callback_query {
                            self.on_callback(cb).await;
                        }
                    }
                }
                Err(e) => {
                    failures += 1;
                    let wait = Duration::from_secs((2u64 << failures.min(6)).min(120));
                    tracing::warn!(error = %format!("{e:#}"), wait_secs = wait.as_secs(), "telegram getUpdates failed");
                    tokio::time::sleep(wait).await;
                }
            }
        }
    }
}

/// Starts the card sender and the update poller. Abort the handles to stop.
pub fn start(
    cfg: &TelegramActionsConfig,
    client: reqwest::Client,
    handle: AlertHandle,
    inventory: Arc<Mutex<Inventory>>,
    silences: Arc<SilenceStore>,
) -> Result<(TgActions, Vec<JoinHandle<()>>)> {
    let token = env_secret(&cfg.bot_token_env)?;
    if !token
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == ':' || c == '_' || c == '-')
    {
        bail!("telegram_actions bot token has an invalid format");
    }
    let api = cfg
        .api_base
        .as_deref()
        .unwrap_or(DEFAULT_API)
        .trim_end_matches('/');
    if !api.starts_with("https://")
        && !api.starts_with("http://127.0.0.1")
        && !api.starts_with("http://localhost")
    {
        bail!("telegram_actions.api_base must be https:// (or loopback http)");
    }
    let shared = Arc::new(Shared {
        cfg: cfg.clone(),
        client,
        base: format!("{api}/bot{token}"),
        pending: Mutex::new((HashMap::new(), VecDeque::new())),
        handle,
        inventory,
        silences,
    });
    let (tx, mut rx) = mpsc::channel::<Card>(256);
    let sender = {
        let s = shared.clone();
        tokio::spawn(async move {
            while let Some(card) = rx.recv().await {
                s.send_card(card).await;
                // Telegram allows about one message per second per chat.
                tokio::time::sleep(Duration::from_millis(1100)).await;
            }
        })
    };
    let poller = tokio::spawn(shared.poll());
    Ok((TgActions { tx }, vec![sender, poller]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> TelegramActionsConfig {
        TelegramActionsConfig {
            bot_token_env: "X".into(),
            chat_id: -100123,
            allowed_user_ids: vec![42],
            mute_days: 7,
            api_base: None,
        }
    }

    fn cb(user: i64, chat: i64, data: &str) -> CallbackQuery {
        serde_json::from_value(serde_json::json!({
            "id": "1", "from": {"id": user, "is_bot": false, "first_name": "x"},
            "message": {"message_id": 9, "chat": {"id": chat, "type": "supergroup"}, "date": 0},
            "data": data,
        }))
        .unwrap()
    }

    #[test]
    fn authorisation_fails_closed() {
        let tok = token("O=CA|01");
        let known = |t: &str| t == tok;
        let c = cfg();
        assert_eq!(
            decide(&c, &cb(42, -100123, &format!("k:{tok}")), known),
            Decision::Do(Action::Known, tok.clone())
        );
        assert_eq!(
            decide(&c, &cb(42, -100123, &format!("m:{tok}")), known),
            Decision::Do(Action::Mute, tok.clone())
        );
        assert_eq!(
            decide(&c, &cb(7, -100123, &format!("k:{tok}")), known),
            Decision::Unauthorized
        );
        assert_eq!(
            decide(&c, &cb(42, -555, &format!("k:{tok}")), known),
            Decision::Unauthorized
        );
        assert_eq!(
            decide(&c, &cb(42, -100123, "k:0000000000000000"), known),
            Decision::Expired
        );
        assert_eq!(decide(&c, &cb(42, -100123, "zz"), known), Decision::Expired);
        assert_eq!(
            decide(&c, &cb(42, -100123, &format!("x:{tok}")), known),
            Decision::Expired
        );
        let kb = keyboard(&tok, 7);
        for b in kb["inline_keyboard"][0].as_array().unwrap() {
            assert!(b["callback_data"].as_str().unwrap().len() <= 64);
        }
    }

    #[test]
    fn actions_update_inventory_silences_and_alerts() {
        let inv = Arc::new(Mutex::new(Inventory::in_memory(10)));
        let cert = crate::notify::sample_alert("example.net").cert;
        inv.lock().unwrap().record(
            &cert,
            "example.net",
            crate::matcher::MatchKind::Subdomain,
            "log",
            0,
        );
        let key = crate::inventory::key(&cert.issuer_dn, &cert.serial_hex);
        let silences = Arc::new(SilenceStore::in_memory());
        let shared = Shared {
            cfg: cfg(),
            client: reqwest::Client::new(),
            base: "https://api.telegram.org/botX".into(),
            pending: Mutex::new((HashMap::new(), VecDeque::new())),
            handle: AlertHandle::disabled(TOOL),
            inventory: inv.clone(),
            silences: silences.clone(),
        };
        let card = Card {
            text: "t".into(),
            key: key.clone(),
            domain: "example.net".into(),
            kind: "certificate".into(),
            title: "New certificate".into(),
        };
        shared.perform(Action::Suspicious, &card, 42).unwrap();
        assert_eq!(
            inv.lock().unwrap().certs[&key].verdict.as_deref(),
            Some("suspicious")
        );
        assert_eq!(
            inv.lock().unwrap().certs[&key].verdict_by.as_deref(),
            Some("telegram:42")
        );
        let msg = shared.perform(Action::Mute, &card, 42).unwrap();
        assert!(msg.starts_with("Muted certificate alerts for example.net"));
        let s = &silences.list()[0];
        assert_eq!(s.resource.as_deref(), Some("example.net"));
        assert_eq!(s.kind.as_deref(), Some("certificate"));
    }
}
