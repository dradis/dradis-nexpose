module Dradis
  module Plugins
    module Nexpose
      # Returns the version of the currently loaded Nexpose as a <tt>Gem::Version</tt>
      def self.gem_version
        Gem::Version.new VERSION::STRING
      end

      module VERSION
        MAJOR = 3
        MINOR = 15
        TINY = 1
        PRE = 'rc1'

        STRING = [MAJOR, MINOR, TINY, PRE].compact.join(".")
      end
    end
  end
end
