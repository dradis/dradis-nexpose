module Dradis::Plugins::Nexpose::Formats

  # This module knows how to parse Nexpose Ful XML format.
  module Full
    private

    def process_full(doc)
      note_text = nil

      @vuln_list = []
      evidence = Hash.new { |h, k| h[k] = {} }

      # First, extract scans
      scan_node = content_service.create_node(label: 'Nexpose Scan Summary')
      logger.info{ "\tProcessing scan summary" }

      doc.xpath('//scans/scan').each do |xml_scan|
        note_text = template_service.process_template(template: 'full_scan', data: xml_scan)
        content_service.create_note(node: scan_node, text: note_text)
      end


      # Second, we parse the nodes
      doc.xpath('//nodes/node').each do |xml_node|
        nexpose_node = Nexpose::Node.new(xml_node)

        host_node = content_service.create_node(label: nexpose_node.address, type: :host)
        logger.info{ "\tProcessing host: #{nexpose_node.address}" }

        # add the summary note for this host
        note_text = template_service.process_template(template: 'full_node', data: nexpose_node)
        content_service.create_note(node: host_node, text: note_text)

        if host_node.respond_to?(:properties)
          logger.info{ "\tAdding host properties: :ip and :hostnames"}
          host_node.set_property(:ip, nexpose_node.address)
          host_node.set_property(:hostnames, nexpose_node.names)
        end

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
            xml_vuln.last_element_child.add_child("<host>#{nexpose_node.address}</host>")
          end

          evidence[test_id][nexpose_node.address] = node_test
        end

        nexpose_node.endpoints.each do |endpoint|
          # endpoint_node = content_service.create_node(label: endpoint.label, parent: host_node)
          logger.info{ "\t\tEndpoint: #{endpoint.label}" }

          if host_node.respond_to?(:properties)
            logger.info{ "\t\tAdding to Services table" }
            host_node.set_property(:services, {
              port: endpoint.port.to_i,
              protocol: endpoint.protocol,
              state: endpoint.status,
              name: endpoint.services.map(&:name).join(', ')
              # reason: port.reason,
              # product: port.try('service').try('product'),
              # version: port.try('service').try('version')
            })
          end

          endpoint.services.each do |service|

            # add the summary note for this service
            note_text = template_service.process_template(template: 'full_service', data: service)
            # content_service.create_note(node: endpoint_node, text: note_text)
            content_service.create_note(node: host_node, text: note_text)

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
                xml_vuln.last_element_child.add_child("<host>#{nexpose_node.address}</host>")
              end

              evidence[test_id][nexpose_node.address] = service_test
            end
          end
        end

        # add note under this node for each vulnerable ./node/test/
        host_node.save
      end

      # Third, parse vulnerability definitions
      definitions_node = content_service.create_node(label: 'Definitions')
      logger.info{ "\tProcessing issue definitions:" }

      doc.xpath('//VulnerabilityDefinitions/vulnerability').each do |xml_vulnerability|
        id = xml_vulnerability['id'].downcase
        # if @vuln_list.include?(id)
          issue_text = template_service.process_template(template: 'full_vulnerability', data: xml_vulnerability)

          # retrieve hosts affected by this issue (injected in step 2)
          #
          # There is no need for the below as Issues are linked to hosts via the
          # corresponding Evidence instance
          #
          # note_text << "\n\n#[host]#\n"
          # note_text << xml_vulnerability.xpath('./hosts/host').collect(&:text).join("\n")
          # note_text << "\n\n"

          # 3.1 create the Issue
          issue = content_service.create_issue(text: issue_text, id: id)
          logger.info{ "\tIssue: #{issue.fields ? issue.fields['Title'] : id}" }


          # 3.2 associate with the nodes via Evidence.
          #   TODO: there is room for improvement here by providing proper Evidence content
          xml_vulnerability.xpath('./hosts/host').collect(&:text).each do |host_name|
            # if the node exists, this just returns it
            host_node = content_service.create_node(label: host_name, type: :host)

            evidence_content = template_service.process_template(template: 'full_evidence', data: evidence[id][host_name])
            content_service.create_evidence(content: evidence_content, issue: issue, node: host_node)
          end

        # end
      end
    end # /parse_nexpose_full_xml
  end
end
