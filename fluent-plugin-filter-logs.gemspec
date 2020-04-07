# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

Gem::Specification.new do |spec|
  spec.name    = 'fluent-plugin-filter-logs'
  spec.version = '1.1.0'
  spec.authors = ['Camille Meulien']
  spec.email   = ['cmeulien@heliostech.fr']

  spec.summary       = 'Logs parser filter plugin for fluentd'
  spec.description   = 'Parse mixed type of logs (JSON, Rails, fmtlogs, ...)'
  spec.homepage      = 'https://github.com/openware/fluent-plugin-filter-logs'
  spec.license       = 'Apache-2.0'

  test_files, files  = `git ls-files -z`.split("\x0").partition do |f|
    f.match(%r{^(test|spec|features)/})
  end
  spec.files         = files
  spec.executables   = files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = test_files
  spec.require_paths = ['lib']
  spec.add_runtime_dependency 'logfmt', '~> 0.0.9'

  spec.add_development_dependency 'byebug'
  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake', '~> 12.0'
  spec.add_development_dependency 'test-unit', '~> 3.0'
  spec.add_runtime_dependency 'fluentd', ['>= 0.14.10', '< 2']
end
