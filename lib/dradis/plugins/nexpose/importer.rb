require 'dradis/plugins/nexpose/formats/full'
require 'dradis/plugins/nexpose/formats/simple'

module Dradis::Plugins::Nexpose
  class Importer < Dradis::Plugins::Upload::Importer

    include Formats::Full
    include Formats::Simple

    # The framework will call this function if the user selects this plugin from
    # the dropdown list and uploads a file.
    # @returns true if the operation was successful, false otherwise
    def import(params={})
      file_content = File.read( params[:file] )

      logger.info { 'Parsing NeXpose output file...' }
      doc = Nokogiri::XML(file_content)
      logger.info { 'Done.' }

      if doc.root.name == 'NeXposeSimpleXML'
        logger.info { 'NeXpose-Simple format detected' }
        process_simple(doc)
      elsif doc.root.name == 'NexposeReport'
        logger.info { 'NeXpose-Full format detected' }
        process_full(doc)
      else
        error = "The document doesn't seem to be in either NeXpose-Simple or NeXpose-Full XML format. Ensure you uploaded a Nexpose XML report."
        logger.fatal{ error }
        content_service.create_note text: error
        return false
      end
    end
  end
end