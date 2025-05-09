# frozen_string_literal: true

source "https://rubygems.org"

gemspec

# Jekyll 및 Chirpy 테마 호환을 위한 버전 고정
gem "jekyll", "~> 4.3.2"
gem "liquid", "~> 4.0.4"


group :test do
  gem "html-proofer", "~> 4.4"
end

# Windows 및 JRuby 대응
platforms :mingw, :x64_mingw, :mswin, :jruby do
  gem "tzinfo", ">= 1", "< 3"
  gem "tzinfo-data"
end

gem "wdm", "~> 0.1.1", :platforms => [:mingw, :x64_mingw, :mswin]