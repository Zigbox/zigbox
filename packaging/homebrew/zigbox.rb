# The Homebrew formula for zbx, for the tap Zigbox/homebrew-tap (brew install Zigbox/tap/zigbox).
# This is the template: `zig build mac-release` fills @VERSION@, @URL@ and @SHA256@ (the archive it
# built) and writes the result to zig-out/mac-release/zigbox.rb, which is what goes in the tap.
#
# It installs the prebuilt, signed and notarized arm64 binary from the GitHub release; it does not
# build from source. Nothing here needs sudo: brew writes only under its own prefix, and zbx makes
# its files in the user's ~/Library/Application Support/zbx the first time it runs.
class Zigbox < Formula
  desc "Rootless container runtime for Linux, and for macOS through a small virtual machine"
  homepage "https://github.com/Zigbox/zigbox"
  url "@URL@"
  version "@VERSION@"
  sha256 "@SHA256@"
  license "MIT"

  depends_on arch: :arm64
  depends_on :macos

  def install
    bin.install "zbx"
  end

  test do
    # Neither command starts the virtual machine.
    assert_match "zbx #{version}", shell_output("#{bin}/zbx --version")
    assert_match "virtualization", shell_output("#{bin}/zbx explain E1001")
  end
end
