module Dradis
  module Plugins
    module Nexpose
    end
  end
end

require 'dradis/plugins/nexpose/engine'
require 'dradis/plugins/nexpose/field_processor'
require 'dradis/plugins/nexpose/importer'
require 'dradis/plugins/nexpose/version'


module Dradis
  module Plugins
    module Nexpose
      # This is required while we transition the Upload Manager to use
      # Dradis::Plugins
      module Meta
        NAME = "NeXpose XML file upload"
        EXPECTS = "NeXpose Simple or Full XML format."

        module VERSION
          include Dradis::Plugins::Nexpose::VERSION
        end
      end
    end
  end
end
