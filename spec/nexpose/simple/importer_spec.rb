# To run, execute from Dradis main app folder:
# bin/rspec [dradis-nexpose path]/spec/nexpose/simple/importer_spec.rb
require 'rails_helper'
require 'ostruct'
require File.expand_path('../../../../../dradis-plugins/spec/support/spec_macros.rb', __FILE__)

include Dradis::Plugins::SpecMacros

module Dradis::Plugins
  describe Nexpose::Simple::Importer do
    before do
      @fixtures_dir = File.expand_path('../../../fixtures/files/', __FILE__)
    end

    before(:each) do
      stub_content_service
      @importer = described_class.new(content_service: @content_service)
    end

    def run_import!
      @importer.import(file: @fixtures_dir + '/simple.xml')
    end

    it 'creates nodes and associated notes as needed' do
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

      run_import!
    end
  end
end
