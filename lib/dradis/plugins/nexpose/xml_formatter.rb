module Dradis::Plugins::Nexpose
  class XmlFormatter
    def cleanup_html(source)
      result = source.to_s
      result.gsub!(/<ContainerBlockElement>(.*?)<\/ContainerBlockElement>/m) { |m| "#{ $1 }" }
      result.gsub!(/<Paragraph preformat=\"true\">(\s*)<Paragraph preformat=\"true\">(.*?)<\/Paragraph>(\s*)<\/Paragraph>/mi) do
        text = $2
        text[/\n/] ? "\nbc.. #{ text }\n\np. " : "@#{text}@"
      end
      result.gsub!(/<Paragraph preformat=\"true\">(.*?)<\/Paragraph>/mi) do
        text = $1
        text[/\n/] ? "\nbc.. #{ text }\n\np. " : "@#{text}@"
      end
      result.gsub!(/<Paragraph>(.*?)<\/Paragraph>/m) { |m| "#{ $1 }\n" }
      result.gsub!(/<Paragraph>|<\/Paragraph>/, '')
      result.gsub!(/          /, '')
      result.gsub!(/   /, '')
      result.gsub!(/\t\t/, '')
      result.gsub!(/<URLLink(.*)LinkURL=\"(.*?)\"(.*?)>(.*?)<\/URLLink>/im) { "\"#{$4.strip}\":#{$2.strip} " }
      result.gsub!(/<URLLink LinkTitle=\"(.*?)\"(.*?)LinkURL=\"(.*?)\"\/>/i) { "\"#{$1.strip}\":#{$3.strip} " }
      result.gsub!(/<URLLink LinkURL=\"(.*?)\"(.*?)LinkTitle=\"(.*?)\"\/>/i) { "\"#{$3.strip}\":#{$1.strip} " }
      result.gsub!(/&gt;/, '>')
      result.gsub!(/&lt;/, '<')
      result
    end

    def cleanup_nested(source)
      result = source.to_s
      result.gsub!(/<references>/, '')
      result.gsub!(/<\/references>/, '')
      result.gsub!(/<reference source=\"(.*?)\">(.*?)<\/reference>/i) { "#{$1.strip}: #{$2.strip}\n" }
      result.gsub!(/<tags>/, '')
      result.gsub!(/<\/tags>/, '')
      result.gsub!(/<tag>(.*?)<\/tag>/) { "#{$1}\n" }
      result.gsub!(/        /, '')
      result
    end

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
        list_item_element = list.name == 'UnorderedList' ? '*' : '#'

        list.xpath('./ListItem').map do |list_item|
          paragraphs = list_item.xpath('./Paragraph')

          list_item_text = if paragraphs.any?
            paragraphs.map do |paragraph|
              # <Paragraph> nodes can either have more lists or just text
              if paragraph.xpath('./UnorderedList | ./OrderedList').any?
                format_nexpose_list(paragraph, depth + 1)
              else
                cleanup_html(paragraph.to_s)
              end
            end.join("\n")
          else
            list_item.text
          end

          ''.ljust(depth, list_item_element) + ' ' + list_item_text
        end.join("\n")
      end.join("\n")
    end
  end
end
