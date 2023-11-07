module Nexpose
  class Test
    def self.new(xml_node)
      content =
        # get first Paragraph or ContainerBlockElement that's a direct child of <test>
        if xml = xml_node.at_xpath('./Paragraph | ./ContainerBlockElement')
          # get all nested paragraph elements
          nested_paragraphs = xml.xpath('.//Paragraph')
          content = []

          nested_paragraphs.children.each do |node|
            case node.name
            when 'text'
              content << node.text.strip
            when 'URLLink'
              content << node['LinkURL']
            end
          end
          content.map(&:strip).reject(&:empty?).join("\n")
        else
          'n/a'
        end

      {
        id: xml_node.attributes['id'],
        status: xml_node.attributes['status'],
        content: content
      }
    end
  end
end
