module Nexpose
  class Test
    def self.new(xml_node)
      content =
        if xml_node.at_xpath('./Paragraph')
          xml_node.
            at_xpath('./Paragraph').
            text.
            split("\n").
            collect(&:strip).
            reject { |line| line.empty? }.join("\n")
        else
          'n/a'
        end

        
        data = {
          id: xml_node.attributes['id'],
          status: xml_node.attributes['status'],
          content: content,
        }

        data.merge!({ port: xml_node.at_xpath('./endpoint/@port').value }) if xml_node.at_xpath('./endpoint/@port')
        data.merge!({ protocol: xml_node.at_xpath('./endpoint/@protocol').value }) if xml_node.at_xpath('./endpoint/@protocol')

        data
    end
  end
end
