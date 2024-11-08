require 'rails_helper'
require 'ostruct'

describe 'Nexpose upload plugin' do
  before do
    @fixtures_dir = File.expand_path('../fixtures/files/', __FILE__)
  end

  describe 'Importer: Full with fingerprints elements' do
    def apply_mapping(doc, field)
      ms = Dradis::Plugins::MappingService.new(
        integration: Dradis::Plugins::Nexpose
      )
      mapping_fields = [OpenStruct.new(
        destination_field: 'Fingerprints',
        content: "{{ nexpose[#{field}] }}"
      )]

      @result = ms.apply_mapping(
        data: doc.at_xpath('//nodes/node'),
        mapping_fields: mapping_fields,
        source: 'full_node'
      )
    end

    describe 'with fingerprints > OS elements' do
      it 'uses the os product value' do
        doc = Nokogiri::XML(File.read(@fixtures_dir + '/full.xml'))
        apply_mapping(doc, 'node.fingerprints')

        expect(@result).to include('IOS')
      end

      it 'defaults to n/a if there is no os product value' do
        doc = Nokogiri::XML(File.read(@fixtures_dir + '/full_with_duplicate_node.xml'))
        apply_mapping(doc, 'node.fingerprints')

        expect(@result).to include('n/a')
      end
    end

    describe 'with software > fingerprint elements' do
      it 'uses the product value given software/fingerprints' do
        doc = Nokogiri::XML(File.read(@fixtures_dir + '/full.xml'))
        apply_mapping(doc, 'node.software')

        expect(@result).to include('JRE')
      end

      it 'defaults to n/a if there is no os product value' do
        doc = Nokogiri::XML(File.read(@fixtures_dir + '/full_with_duplicate_node.xml'))
        apply_mapping(doc, 'node.software')

        expect(@result).to include('n/a')
      end
    end
  end
end
