module Dradis::Plugins::Nexpose
  module Simple
    def self.meta
      package = Dradis::Plugins::Nexpose
      {
        name: package::Engine::plugin_name,
        description: 'Upload Simple NeXpose output file (.xml)',
        version: package.version
      }
    end

    class Importer < Dradis::Plugins::Upload::Importer
      def self.templates
        {}
      end

      def initialize(args = {})
        args[:plugin] = Dradis::Plugins::Nexpose
        super(args)
      end

      # The framework will call this function if the user selects this plugin from
      # the dropdown list and uploads a file.
      # @returns true if the operation was successful, false otherwise
      def import(params = {})
        file_content = File.read( params[:file] )

        logger.info { 'Parsing NeXpose output file...' }
        doc = Nokogiri::XML(file_content)
        logger.info { 'Done.' }

        unless doc.root.name == 'NeXposeSimpleXML'
          error = "The document doesn't seem to be in either NeXpose-Simple or NeXpose-Full XML format. Ensure you uploaded a Nexpose XML report."
          logger.fatal{ error }
          content_service.create_note text: error
          return false
        end

        process_simple(doc)

        logger.info { 'NeXpose-Simple format uploaded successfully' }
        true
      end

      private

      def process_simple(doc)
        hosts = process_nexpose_simple_xml(doc)
        notes_simple(hosts)
      end

      def notes_simple(hosts)
        return if hosts.nil?

        hosts.each do |host|
          host_node = content_service.create_node(label: host['address'], type: :host)
          content_service.create_note node: host_node, text: "Host Description : #{host['description']} \nScanner Fingerprint certainty : #{host['fingerprint']}"

          generic_findings_node = content_service.create_node(label: 'Generic Findings', parent: host_node)
          host['generic_vulns'].each do |id, finding|
            content_service.create_note node: generic_findings_node, text: "Finding ID : #{id} \n \n Finding Refs :\n-------\n #{finding}"
          end

          port_text = nil
          host['ports'].each do |port_label, findings|
            port_node = content_service.create_node(label: port_label, parent: host_node)

            findings.each do |id, finding|
              port_text = mapping_service.apply_mapping(source: 'simple_port', data: {id: id, finding: finding})
              port_text << "\n#[host]#\n#{host['address']}\n\n"
              content_service.create_note node: port_node, text: port_text
            end
          end
        end
      end

      def process_nexpose_simple_xml(doc)
        results = doc.search('device')
        hosts = Array.new
        results.each do |host|
          current_host = Hash.new
          current_host['address'] = host['address']
          current_host['fingerprint'] = host.search('fingerprint')[0].nil? ? "N/A" : host.search('fingerprint')[0]['certainty']
          current_host['description'] = host.search('description')[0].nil? ? "N/A" : host.search('description')[0].text
          #So there's two sets of vulns in a NeXpose simple XML report for each host
          #Theres some generic ones at the top of the report
          #And some service specific ones further down the report.
          #So we need to get the generic ones before moving on
          current_host['generic_vulns'] = Hash.new
          host.xpath('vulnerabilities/vulnerability').each do |vuln|
            current_host['generic_vulns'][vuln['id']] = ''
            vuln.xpath('id').each do |id|
              current_host['generic_vulns'][vuln['id']] << id['type'] + " : " + id.text + "\n"
            end
          end

          current_host['ports'] = Hash.new
          host.xpath('services/service').each do |service|
            protocol = service['protocol']
            portid = service['port']
            port_label = protocol + '-' + portid
            current_host['ports'][port_label] = Hash.new
            service.xpath('vulnerabilities/vulnerability').each do |vuln|
              current_host['ports'][port_label][vuln['id']] = ''
              vuln.xpath('id').each do |id|
                current_host['ports'][port_label][vuln['id']] << id['type'] + " : " + id.text + "\n"
              end
            end
          end

          hosts << current_host
        end
        return hosts
      end
    end
  end
end
