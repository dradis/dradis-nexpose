module Dradis::Plugins::Nexpose
  class Engine < ::Rails::Engine
    isolate_namespace Dradis::Plugins::Nexpose

    include ::Dradis::Plugins::Base
    description 'Processes Nexpose XML format'
    provides :upload

    # Because this plugin provides two export modules, we have to overwrite
    # the default .uploaders() method.
    #
    # See:
    #  Dradis::Plugins::Upload::Base in dradis-plugins
    def self.uploaders
      [
        Dradis::Plugins::Nexpose::Full,
        Dradis::Plugins::Nexpose::Simple
      ]
    end
  end
end
