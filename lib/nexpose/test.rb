module Nexpose
  class Test
    def self.new(xml_node)
      content =
        # get first Paragraph or ContainerBlockElement that's a direct child of <test>
        if xml = xml_node.at_xpath('./Paragraph | ./ContainerBlockElement')
          # get all nested paragraph elements
          nested_paragraphs = xml.xpath('.//Paragraph')

          content = nested_paragraphs.children.map do |node|
            case node.name
            when 'text'
              node.text.strip
            when 'URLLink'
              node['LinkURL']
            end
          end.compact
          content.map(&:strip).reject(&:empty?).join("\n")
        else
          'n/a'
        end

      {
        id: xml_node.attributes['id'],
        status: xml_node.attributes['status'],
        content: content,
        port: xml_node.attributes['port'],
        protocol: xml_node.attributes['protocol']
      }
    end
  end
end
