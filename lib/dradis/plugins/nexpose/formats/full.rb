module Dradis::Plugins::Nexpose::Formats

  # This module knows how to parse Nexpose Ful XML format.
  module Full
    def parse_full(doc)
      parse_nexpose_full_xml(doc)
    end

    private


    def parse_nexpose_full_xml(doc)
      note_text = nil

      @vuln_list = []
      details = {}
      hosts = Array.new

      # First, extract scans
      scan_node = @parent.children.find_or_create_by_label('Nexpose Scan Summary')

      doc.xpath('//scans/scan').each do |xml_scan|
        note_text = process_entry('full_scan', xml_scan)

        Note.create(
          :node => scan_node,
          :author => @author,
          :category => @category,
          :text => note_text
        )
      end


      # Second, we parse the nodes
      doc.xpath('//nodes/node').each do |xml_node|
        nexpose_node = Nexpose::Node.new(xml_node)

        node_node = @parent.children.find_or_create_by_label_and_type_id(nexpose_node.address, Node::Types::HOST)

        # add the summary note for this host
        note_text = process_entry('full_node', nexpose_node)
        Note.create(
          :node => node_node,
          :author => @author,
          :category => @category,
          :text => note_text
        )

        # inject this node's address into any vulnerabilities identified
        #
        # TODO: There is room for improvement here, we could have a hash that
        # linked vulns with test/service and host to create proper content for
        # Evidence.
        nexpose_node.tests.each do |node_test|
          test_id = node_test[:id].to_s.downcase

          # We can't use the straightforward version below because Nexpose uses
          # mixed-case some times (!)
          #   xml_vuln = doc.xpath("//VulnerabilityDefinitions/vulnerability[@id='#{node_test[:id]}']").first
          # See:
          #   http://stackoverflow.com/questions/1625446/problem-with-upper-case-and-lower-case-xpath-functions-in-selenium-ide/1625859#1625859
          xml_vuln = doc.xpath("//VulnerabilityDefinitions/vulnerability[translate(@id,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='#{test_id}']").first
          xml_vuln.add_child("<hosts/>") unless xml_vuln.last_element_child.name == "hosts"

          if xml_vuln.xpath("./hosts/host[text()='#{nexpose_node.address}']").empty?
            xml_vuln.last_element_child.add_child( "<host>#{nexpose_node.address}</host>")
          end
        end

        nexpose_node.endpoints.each do |endpoint|
          endpoint_node = node_node.children.find_or_create_by_label(endpoint.label)

          endpoint.services.each do |service|

            # add the summary note for this service
            note_text = process_entry('full_service', service)
            Note.create(
              :node => endpoint_node,
              :author => @author,
              :category => @category,
              :text => note_text
            )

            # inject this node's address into any vulnerabilities identified
            service.tests.each do |service_test|
              test_id = service_test[:id].to_s.downcase

              # For some reason Nexpose fails to include the 'http-iis-0011' vulnerability definition
              next if test_id == 'http-iis-0011'

              # We can't use the straightforward version below because Nexpose uses
              # mixed-case some times (!)
              #   xml_vuln = doc.xpath("//VulnerabilityDefinitions/vulnerability[@id='#{service_test[:id]}']").first
              # See:
              #   http://stackoverflow.com/questions/1625446/problem-with-upper-case-and-lower-case-xpath-functions-in-selenium-ide/1625859#1625859
              #
              xml_vuln = doc.xpath("//VulnerabilityDefinitions/vulnerability[translate(@id,'ABCDEFGHIJKLMNOPQRSTUVWXYZ','abcdefghijklmnopqrstuvwxyz')='#{test_id}']").first
              xml_vuln.add_child("<hosts/>") unless xml_vuln.last_element_child.name == "hosts"

              if xml_vuln.xpath("./hosts/host[text()='#{nexpose_node.address}']").empty?
                xml_vuln.last_element_child.add_child( "<host>#{nexpose_node.address}</host>")
              end
            end
          end
        end

        # add note under this node for each vulnerable ./node/test/
      end

      # Third, parse vulnerability definitions
      definitions = Node.create(:label => "Definitions", :parent_id => @parent.id)

      doc.xpath('//VulnerabilityDefinitions/vulnerability').each do |xml_vulnerability|
        id = xml_vulnerability['id'].downcase
        # if @vuln_list.include?(id)
          issue_text = process_entry('full_vulnerability', xml_vulnerability)

          # retrieve hosts affected by this issue (injected in step 2)
          #
          # There is no need for the below as Issues are linked to hosts via the
          # corresponding Evidence instance
          #
          # note_text << "\n\n#[host]#\n"
          # note_text << xml_vulnerability.xpath('./hosts/host').collect(&:text).join("\n")
          # note_text << "\n\n"

          # 3.1 create the Issue
          issue = Issue.create(:text => issue_text) do |i|
            i.author = @author
            i.node = @issuelib
            i.category = @category
          end

          # 3.2 associate with the nodes via Evidence.
          #   TODO: there is room for improvement here by providing proper Evidence content
          xml_vulnerability.xpath('./hosts/host').collect(&:text).each do |host_name|
            host_node = @parent.children.where(:label => host_name, :type_id => Node::Types::HOST).first
            host_node.evidence.create(:issue_id => issue.id, :content => "N/A")
          end

        # end
      end
    end # /parse_nexpose_full_xml
  end
end