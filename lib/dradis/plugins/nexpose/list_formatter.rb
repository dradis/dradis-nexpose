module Dradis::Plugins::Nexpose
  class ListFormatter
    def format_list(source)
      # Add <root> node in case the source is an invalid xml
      xml = Nokogiri::XML("<root>#{source}</root>") { |conf| conf.noblanks }
      xml = xml.at_xpath('./root/ContainerBlockElement')

      return source unless xml

      if xml.xpath('./UnorderedList | ./OrderedList').any?
        format_nexpose_list(xml)
      else
        source
      end
    end

    private

    def format_nexpose_list(xml, depth = 1)
      xml.xpath('./UnorderedList | ./OrderedList').map do |list|
        list_type = list.name == 'UnorderedList' ? '*' : '#'

        list.xpath('./ListItem').map do |list_item|
          paragraphs = list_item.xpath('./Paragraph')

          if paragraphs.any?
            paragraphs.map do |paragraph|
              # <Paragraph> nodes can either have more lists or just text
              if paragraph.xpath('./UnorderedList | ./OrderedList').any?
                format_nexpose_list(paragraph, depth + 1)
              else
                ''.ljust(depth, list_type) + ' ' + paragraph.text
              end
            end.join("\n")
          else
            ''.ljust(depth, list_type) + ' ' + list_item.text
          end
        end.join("\n")
      end.join("\n")
    end
  end
end
