# To run, execute from Dradis main app folder:
# bin/rspec [dradis-nexpose path]/spec/nexpose/full/importer_spec.rb
require 'rails_helper'
require 'ostruct'
require File.expand_path('../../../../../dradis-plugins/spec/support/spec_macros.rb', __FILE__)

include Dradis::Plugins::SpecMacros

module Dradis::Plugins
  describe Nexpose::Full::Importer do
    before do
      @fixtures_dir = File.expand_path('../../../fixtures/files/', __FILE__)
    end

    before(:each) do
      stub_content_service
      @importer = described_class.new(content_service: @content_service)
    end

    def run_import!
      @importer.import(file: @fixtures_dir + '/full.xml')
    end

    it 'creates nodes and associated notes as needed' do
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
        expect(args[:text]).to include("#[Fingerprints]#\nIOS")
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

      run_import!
    end

    it 'creates issues from vulnerability elements as needed' do
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

      run_import!
    end

    it 'creates evidence as needed' do
      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include('The following NTP variables were found from a readvar')
        expect(args[:issue].id).to eq('ntp-clock-variables-disclosure')
        expect(args[:node].label).to eq('1.1.1.1')
      end.once

      expect(@content_service).to receive(:create_evidence) do |args|
        expect(args[:content]).to include('Missing HTTP header "Content-Security-Policy"')
        expect(args[:issue].id).to eq('test-02')
        expect(args[:node].label).to eq('1.1.1.1')
      end

      run_import!
    end

    describe 'With duplicate nodes' do
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
end
