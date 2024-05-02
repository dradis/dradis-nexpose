require 'rails_helper'
require 'ostruct'

describe 'Nexpose upload plugin' do
  before do
    @fixtures_dir = File.expand_path('../fixtures/files/', __FILE__)
  end

  describe 'importer' do
    before(:each) do
      # Init services
      plugin = Dradis::Plugins::Nexpose

      @content_service = Dradis::Plugins::ContentService::Base.new(
        logger: Logger.new(STDOUT),
        plugin: plugin
      )

      @importer = plugin::Importer.new(
        content_service: @content_service
      )

      # Stub dradis-plugins methods
      #
      # They return their argument hashes as objects mimicking
      # Nodes, Issues, etc
      allow(@content_service).to receive(:create_node) do |args|
        OpenStruct.new(args)
      end
      allow(@content_service).to receive(:create_note) do |args|
        OpenStruct.new(args)
      end
      allow(@content_service).to receive(:create_issue) do |args|
        OpenStruct.new(args)
      end
      allow(@content_service).to receive(:create_evidence) do |args|
        OpenStruct.new(args)
      end
    end

    describe 'Importer: Simple' do
      it 'creates nodes, issues, notes and an evidences as needed' do
        expect(@content_service).to receive(:create_node).with(hash_including label: '1.1.1.1', type: :host).once

        expect(@content_service).to receive(:create_note) do |args|
          expect(args[:text]).to include('Host Description : Linux 2.6.9-89.ELsmp')
          expect(args[:text]).to include('Scanner Fingerprint certainty : 0.80')
          expect(args[:node].label).to eq('1.1.1.1')
        end.once

        expect(@content_service).to receive(:create_node) do |args|
          expect(args[:label]).to eq('Generic Findings')
          expect(args[:parent].label).to eq('1.1.1.1')
          OpenStruct.new(args)
        end.once

        expect(@content_service).to receive(:create_node) do |args|
          expect(args[:label]).to eq('udp-000')
          expect(args[:parent].label).to eq('1.1.1.1')
          OpenStruct.new(args)
        end.once

        expect(@content_service).to receive(:create_note) do |args|
          expect(args[:text]).to include("#[Id]#\nntpd-crypto")
          expect(args[:text]).to include("#[host]#\n1.1.1.1")
          expect(args[:node].label).to eq('udp-000')
        end.once

        expect(@content_service).to receive(:create_note) do |args|
          expect(args[:text]).to include("#[Id]#\nntp-clock-radio")
          expect(args[:text]).to include("#[host]#\n1.1.1.1")
          expect(args[:node].label).to eq('udp-000')
        end.once

        @importer.import(file: @fixtures_dir + '/simple.xml')
      end
    end

    describe 'Importer: Full' do
      it 'creates nodes, issues, notes and an evidences as needed' do
        expect(@content_service).to receive(:create_node).with(hash_including label: 'Nexpose Scan Summary').once
        expect(@content_service).to receive(:create_note) do |args|
          expect(args[:text]).to include("#[Title]#\nUSDA_Internal (4)")
          expect(args[:node].label).to eq('Nexpose Scan Summary')
        end.once

        expect(@content_service).to receive(:create_node) do |args|
          expect(args[:label]).to eq('1.1.1.1')
          expect(args[:type]).to eq(:host)
          create(:node, args.except(:type))
        end

        expect(@content_service).to receive(:create_note) do |args|
          expect(args[:text]).to include("#[Title]#\n1.1.1.1")
          expect(args[:node].label).to eq('1.1.1.1')
        end.once

        expect(@content_service).to receive(:create_note) do |args|
          expect(args[:text]).to include("#[Title]#\nService name: NTP")
          expect(args[:node].label).to eq('1.1.1.1')
        end.once

        expect(@content_service).to receive(:create_note) do |args|
          expect(args[:text]).to include("#[Title]#\nService name: SNMP")
          expect(args[:node].label).to eq('1.1.1.1')
        end.once

        expect(@content_service).to receive(:create_issue) do |args|
          expect(args[:text]).to include("#[Title]#\nApache HTTPD: error responses can expose cookies (CVE-2012-0053)")
          expect(args[:id]).to eq('ntp-clock-variables-disclosure')
          OpenStruct.new(args)
        end.once

        expect(@content_service).to receive(:create_issue) do |args|
          expect(args[:text]).to include("#[Title]#\nApache HTTPD: ETag Inode Information Leakage (CVE-2003-1418)")
          expect(args[:id]).to eq('test-02')
          OpenStruct.new(args)
        end.once

        expect(@content_service).to receive(:create_evidence) do |args|
          expect(args[:content]).to include("#[ID]#\nntp-clock-variables-disclosure\n\n")
          expect(args[:issue].id).to eq('ntp-clock-variables-disclosure')
          expect(args[:node].label).to eq('1.1.1.1')
        end.once

        expect(@content_service).to receive(:create_evidence) do |args|
          expect(args[:content]).to include("#[ID]#\ntest-02\n\n")
          expect(args[:issue].id).to eq('test-02')
          expect(args[:node].label).to eq('1.1.1.1')
        end.once

        @importer.import(file: @fixtures_dir + '/full.xml')

        expect(Node.find_by(label: '1.1.1.1').properties[:os]).to eq('IOS')
      end

      it 'wraps ciphers inside ssl issues in code blocks' do
        expect(@content_service).to receive(:create_issue) do |args|
          expect(args[:text]).to include('bc. ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256')
          OpenStruct.new(args)
        end.once

        @importer.import(file: @fixtures_dir + '/ssl.xml')
      end

      # Regression test for github.com/dradis/dradis-nexpose/issues/1
      it 'populates solutions regardless of if they are wrapped in paragraphs or lists' do
        expect(@content_service).to receive(:create_issue) do |args|
          expect(args[:text]).to include("#[Solution]#\n\nApache HTTPD >= 2.0 and < 2.0.65")
          OpenStruct.new(args)
        end.once

        expect(@content_service).to receive(:create_issue) do |args|
          expect(args[:text]).to include("#[Solution]#\n")
          expect(args[:text]).to include('You can remove inode information from the ETag header')
          OpenStruct.new(args)
        end.once

        @importer.import(file: @fixtures_dir + '/full.xml')
      end

      it 'populates tests regardless of if they contain paragraphs or containerblockelements' do
        expect(@content_service).to receive(:create_evidence) do |args|
          expect(args[:content]).to include("#[Content]#\nThe following NTP variables")
          OpenStruct.new(args)
        end.once

        expect(@content_service).to receive(:create_evidence) do |args|
          expect(args[:content]).to include("#[Content]#\nVulnerable URL:")
          OpenStruct.new(args)
        end.once

        @importer.import(file: @fixtures_dir + '/full.xml')
      end

      it 'transforms html entities (&lt; and &gt;)' do
        expect(@content_service).to receive(:create_issue) do |args|
          expect(args[:text]).to include("#[Solution]#\n\nApache HTTPD >= 2.0 and < 2.0.65")
          OpenStruct.new(args)
        end

        @importer.import(file: @fixtures_dir + '/full.xml')
      end
    end

    describe 'Importer: Full with duplicate nodes' do
      it 'creates evidence for each instance of the node' do
        expect(@content_service).to receive(:create_node).with(hash_including label: 'Nexpose Scan Summary').once
        expect(@content_service).to receive(:create_node) do |args|
          expect(args[:label]).to eq('1.1.1.1')
          expect(args[:type]).to eq(:host)
          create(:node, args.except(:type))
        end

        expect(@content_service).to receive(:create_evidence) do |args|
          expect(args[:content]).to include("#[ID]#\nntp-clock-variables-disclosure\n\n")
          expect(args[:issue].id).to eq('ntp-clock-variables-disclosure')
          expect(args[:node].label).to eq('1.1.1.1')
        end.twice

        @importer.import(file: @fixtures_dir + '/full_with_duplicate_node.xml')
      end
    end
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
