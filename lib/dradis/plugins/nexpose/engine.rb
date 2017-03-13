module Dradis::Plugins::Nexpose
  class Engine < ::Rails::Engine
    isolate_namespace Dradis::Plugins::Nexpose

    include ::Dradis::Plugins::Base
    description 'Processes Nexpose XML format'
    provides :upload
  end
end
