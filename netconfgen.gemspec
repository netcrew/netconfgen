# coding: utf-8
#

Gem::Specification.new do |s|
  s.name          = 'netconfgen'
  s.version       = '0.0.1'
  s.date          = Time.now

  s.summary       = %q{Template based config generation}
  s.files         = `git ls-files`.split("\n")
  s.executables   = ['confgen']
  s.test_files    = s.files.grep(%r{^test/})
  s.require_paths = ['lib']
  s.authors       = "Juho Mäkinen juho.makinen@gmail.com"

  s.required_ruby_version = '>= 2.1.0'

  s.add_development_dependency 'rubygems-tasks', '~> 0.2'
  s.add_development_dependency 'minitest', '~> 5.4'
  s.add_development_dependency 'rake', '~> 10.0'
end
