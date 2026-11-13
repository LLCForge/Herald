# Homebrew formula for Herald.
# Rendered by sync.py; @VERSION@ and the @SHA256_*@ values are filled in by the
# release workflow (job "publish", step "Render package-manager manifests") and
# shipped in herald-<version>-package-manifests.tar.gz. Copy the rendered file
# into the tap repository (LLCForge/homebrew-tap, Formula/herald.rb).
class Herald < Formula
  desc "Certificate Transparency log monitor with typosquat, CAA and expiry alerts"
  homepage "https://github.com/LLCForge/Herald"
  version "@VERSION@"
  license "MIT"

  on_macos do
    on_arm do
      url "https://github.com/LLCForge/Herald/releases/download/v@VERSION@/herald-@VERSION@-aarch64-apple-darwin.tar.gz"
      sha256 "@SHA256_AARCH64_APPLE_DARWIN@"
    end
    on_intel do
      url "https://github.com/LLCForge/Herald/releases/download/v@VERSION@/herald-@VERSION@-x86_64-apple-darwin.tar.gz"
      sha256 "@SHA256_X86_64_APPLE_DARWIN@"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/LLCForge/Herald/releases/download/v@VERSION@/herald-@VERSION@-aarch64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_AARCH64_LINUX_MUSL@"
    end
    on_intel do
      url "https://github.com/LLCForge/Herald/releases/download/v@VERSION@/herald-@VERSION@-x86_64-unknown-linux-musl.tar.gz"
      sha256 "@SHA256_X86_64_LINUX_MUSL@"
    end
  end

  def install
    bin.install "herald"
    pkgetc.install "herald.example.toml" if File.exist?("herald.example.toml")
    doc.install Dir["README*.md"]
  end

  service do
    run [opt_bin/"herald", "run", "--config", etc/"herald/herald.toml"]
    environment_variables STATE_DIRECTORY: var/"lib/herald"
    keep_alive successful_exit: false
    log_path var/"log/herald.log"
    error_log_path var/"log/herald.log"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/herald --version")
  end
end
