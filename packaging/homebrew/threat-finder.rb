class ThreatFinder < Formula
  desc "Runtime vulnerability scanner that flags network-exposed CVEs on a host"
  homepage "https://github.com/offseq/threat-finder"
  version "0.1.0"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    on_arm do
      url "https://github.com/offseq/threat-finder/releases/download/v0.1.0/threat-finder-v0.1.0-aarch64-apple-darwin.tar.gz"
      sha256 "b62d022cd65360803a3782913bd25a361bc4dc92cd63a46e99a1950b538b6ace"
    end
    on_intel do
      url "https://github.com/offseq/threat-finder/releases/download/v0.1.0/threat-finder-v0.1.0-x86_64-apple-darwin.tar.gz"
      sha256 "718d245f044d4a070d218b431a894cd1a9966af512a5d1835309b649762b734d"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/offseq/threat-finder/releases/download/v0.1.0/threat-finder-v0.1.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "e9729c450d16c24a2d91e99f75cfba6f74fa7307c39ecc8802cb741873ed4104"
    end
    on_intel do
      url "https://github.com/offseq/threat-finder/releases/download/v0.1.0/threat-finder-v0.1.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "7c31274ef1efeba3d14287772ee04df2661faa7c65bbd30f911af6123a56810c"
    end
  end

  def install
    bin.install "threat-finder"
  end

  test do
    assert_match "threat-finder #{version}", shell_output("#{bin}/threat-finder --version")
  end
end
