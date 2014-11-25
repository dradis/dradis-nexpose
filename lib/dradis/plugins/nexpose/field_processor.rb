module Dradis::Plugins::Nexpose

  # This processor defers to ::Acunetix::Scan for the scan template and to
  # ::Acunetix::ReportItem for the report_item and evidence templates.
  class FieldProcessor < Dradis::Plugins::Upload::FieldProcessor

    def post_initialize(args={})
      if data.kind_of?(Hash) ||
          data.kind_of?(Nexpose::Scan) ||
          data.kind_of?(Nexpose::Node) ||
          data.kind_of?(Nexpose::Service) ||
          data.kind_of?(Nexpose::Vulnerability)
        @nexpose_object = data
      else
        # XML from Plugin Manager
        if (data.name == 'scan')
          @nexpose_object = Nexpose::Scan.new(entry)
        elsif (data.name == 'node')
          # Full - node
          @nexpose_object = Nexpose::Node.new(entry)
        elsif (data.name == 'service')
          # Full - service
          @nexpose_object = Nexpose::Service.new(entry)
        else
          if data['added']
            # Full - vulnerability
            @nexpose_object = Nexpose::Vulnerability.new(entry)
          else
            # Simple - port
            @nexpose_object = {
              id: entry['id'],
              finding: data.xpath('//id').collect{ |id_node| "#{id_node['type']} : #{id_node.text}" }.join("\n")
            }
          end
        end
      end
    end

    def value(args={})
      field = args[:field]

      # fields in the template are of the form <foo>.<field>, where <foo>
      # is common across all fields for a given template (and meaningless).
      _, name = field.split('.')

      # Simple - port
      if @nexpose_object.kind_of?(Hash)
        @nexpose_object[name.to_sym]
      else
        # Full - scan / node / service vulnerability
        result = @nexpose_object.try(name, nil)
        if result.kind_of?(Array)
          result << 'n/a' if result.empty?
          if result.first.is_a?(String)
            result.join("\n")
          else
            # we have an array of hashes
            format_array_as_table(result)
          end
        else
          result || 'n/a'
        end
      end
    end

    private
    # Return an array as a table:
    #
    #   [
    #     {:a => 1, :b => 2},
    #     {:a => 3, :b => 4}
    #   ]
    #
    # becomes
    #
    #  |_. a |_. b |
    #  | 1 | 2 |
    #  | 3 | 4 |
    #
    def format_array_as_table(array)
      rows = []
      rows << "|_. #{array.first.keys.join(' |_. ')} |"
      array.each do |hash|
        rows << "| #{hash.collect{|_,v| v}.join(" | ")} |"
      end
      rows.join("\n")
    end
  end
end