module Dradis::Plugins::Nexpose
  class Engine < ::Rails::Engine
    isolate_namespace Dradis::Plugins::Nexpose

    include ::Dradis::Plugins::Base
    description 'Processes Nexpose XML format'
    provides :upload

    #     generators do
    #       require "path/to/my_railtie_generator"
    #     end

    # Configuring the gem
    # class Configuration < Core::Configurator
    #   configure :namespace => 'burp'
    #   setting :category, :default => 'Burp Scanner output'
    #   setting :author, :default => 'Burp Scanner plugin'
    # end
  end
end