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
        elsif xml_node.at_xpath('./ContainerBlockElement')
          #Tests that start with <ContainerBlockElement> tags may contain URLLink tags that need to be separately parsed
          result = xml_node.at_xpath('./ContainerBlockElement').to_s
          result.gsub!(/<URLLink(.*)LinkURL=\"(.*?)\"(.*?)>(.*?)<\/URLLink>/im) { "\"#{$4.strip}\":#{$2.strip} " }
          result.gsub!(/<URLLink LinkTitle=\"(.*?)\"(.*?)LinkURL=\"(.*?)\"\/>/i) { "\"#{$1.strip}\":#{$3.strip} " }
          result.gsub!(/<URLLink LinkURL=\"(.*?)\"(.*?)LinkTitle=\"(.*?)\"\/>/i) { "\"#{$3.strip}\":#{$1.strip} " }
          result.gsub!(/<ContainerBlockElement>(.*?)<\/ContainerBlockElement>/m){|m| "#{ $1 }\n"}
          result.gsub!(/<Paragraph>(.*?)<\/Paragraph>/m){|m| "#{ $1 }\n"}
          result.gsub!(/<Paragraph>|<\/Paragraph>/, '')
          result.gsub!(/^\s+/, "")
          result
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
