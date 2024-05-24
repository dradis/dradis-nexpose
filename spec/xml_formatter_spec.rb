# Run the spec by running the command: rspec spec/xml_formatter_spec.rb"

require 'spec_helper'

describe Dradis::Plugins::Nexpose::XmlFormatter do
  let(:source) { File.read(File.expand_path('../fixtures/files/lists.xml', __FILE__)) }

  it 'parses the <UnorderedList> and <OrderedList> elements' do
    expect(Dradis::Plugins::Nexpose::XmlFormatter.new.format_list(source)).to eq(
      "* Microsoft Windows\n"\
      "## Open the Windows Control Panel.\n"\
      "## Select \"Administrative Tools\".\n"\
      "* Microsoft Windows\n"\
      "## Open the \"Performance and Maintenance\" control panel.\n"\
      "## Select \"Administrative Tools\".\n"\
      "## Restart the system for the changes to take effect.\n"\
      "* Microsoft Windows\n"\
      "## Open the \"Administrative Tools\" control panel.\n"\
      '## Restart the system for the changes to take effect.'
    )
  end
end
