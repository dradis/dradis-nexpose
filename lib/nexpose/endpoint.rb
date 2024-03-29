module Nexpose
  # This class represents each of the /NexposeReport[@version='1.0']/nodes/node/endpoints/endpoint
  # elements in the Nexpose Full XML document.
  #
  # It provides a convenient way to access the information scattered all over
  # the XML in attributes and nested tags.
  #
  # Instead of providing separate methods for each supported property we rely
  # on Ruby's #method_missing to do most of the work.
  class Endpoint
    # Accepts an XML node from Nokogiri::XML.
    def initialize(xml_node)
      @xml = xml_node
    end

    # List of supported tags. They can be attributes, simple descendans or
    # collections (e.g. <references/>, <tags/>)
    def supported_tags
      [
        # meta
        :label,

        # attributes
        :protocol, :port, :status,

        # simple tags

        # multiple tags
        :services
      ]
    end

    # Save some time with a meta attribute, e.g. 80/tcp (open)
    def label
      "#{self.port}/#{self.protocol} (#{self.status})"
    end

    # Each of the services associated with this endpoint. Returns an array of
    # Nexpose::Service objects
    def services
      @xml.xpath('./services/service').map do |xml_service|
        Service.new(xml_service, endpoint: { port: port, protocol: protocol })
      end
    end

    # This allows external callers (and specs) to check for implemented
    # properties
    def respond_to?(method, include_private = false)
      return true if supported_tags.include?(method.to_sym)
      super
    end

    # This method is invoked by Ruby when a method that is not defined in this
    # instance is called.
    #
    # In our case we inspect the @method@ parameter and try to find the
    # attribute, simple descendent or collection that it maps to in the XML
    # tree.
    def method_missing(method, *args)
      # We could remove this check and return nil for any non-recognized tag.
      # The problem would be that it would make tricky to debug problems with
      # typos. For instance: <>.potr would return nil instead of raising an
      # exception
      unless supported_tags.include?(method)
        super
        return
      end

      # First we try the attributes. In Ruby we use snake_case, but in XML
      # CamelCase is used for some attributes
      translations_table = {}

      method_name = translations_table.fetch(method, method.to_s)
      return @xml.attributes[method_name].value if @xml.attributes.key?(method_name)

      return nil
    end
  end
end
