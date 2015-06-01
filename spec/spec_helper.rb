require 'rubygems'
require 'bundler/setup'
require 'nokogiri'

require 'combustion'

Combustion.initialize!

RSpec.configure do |config|
  # Enable colors
  config.color = true
  # Use the specified formatter
  config.formatter = :documentation

  # Filter which specs to run
  config.filter_run :focus => true
  config.run_all_when_everything_filtered = true
end
