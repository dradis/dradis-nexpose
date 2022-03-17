module Dradis::Plugins::Nexpose
  class Engine < ::Rails::Engine
    isolate_namespace Dradis::Plugins::Nexpose

    include ::Dradis::Plugins::Base
    description 'Processes Nexpose XML format'
    provides :upload

    def self.template_names
      { module_parent => { evidence: 'full_evidence', issue: 'full_vulnerability' } }
    end
  end
end
