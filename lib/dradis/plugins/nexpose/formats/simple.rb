module Dradis::Plugins::Nexpose::Formats

  # This module knows how to parse Nexpose Simple XML format.
  module Simple
    def parse_simple(doc)
      hosts = parse_nexpose_simple_xml(doc)
      notes_simple(hosts)
    end

    private

    def notes_simple(hosts)
      return if hosts.nil?

      hosts.each do |host|
        host_node = @parent.children.find_or_create_by_label_and_type_id(host['address'], Node::Types::HOST)
        Note.create(
        :node => host_node,
        :author => @author,
        :category => @category,
        :text => "Host Description : #{host['description']} \nScanner Fingerprint certainty : #{host['fingerprint']}"
        )

        generic_findings_node = Node.create(:label => "Generic Findings", :parent_id => host_node.id )
        host['generic_vulns'].each do |id, finding|
          Note.create(
          :node => generic_findings_node,
          :author => @author,
          :category => @category,
          :text => "Finding ID : #{id} \n \n Finding Refs :\n-------\n #{finding}"
          )
        end

        port_text = nil
        host['ports'].each do |port_label, findings|
          port_node = Node.create(:label => port_label, :parent_id => host_node.id)

          findings.each do |id, finding|
            port_text = process_entry('simple_port', {:id => id, :finding => finding})
            port_text << "\n#[host]#\n#{host['address']}\n\n"
            Note.create(
            :node => port_node,
            :author => @author,
            :category => @category,
            :text => port_text
            )
          end
        end
      end
    end

    def parse_nexpose_simple_xml(doc)
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
