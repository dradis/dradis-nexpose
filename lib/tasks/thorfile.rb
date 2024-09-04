class NexposeTasks < Thor
  include Rails.application.config.dradis.thor_helper_module

  namespace "dradis:plugins:nexpose"

  desc "upload_full FILE", "upload NeXpose full results"
  def upload_full(file_path)
    detect_and_set_project_scope

    importer = Dradis::Plugins::Nexpose::Full::Importer.new(task_options)
    importer.import(file: file_path)
  end

  desc "upload_simple FILE", "upload NeXpose simple results"
  def upload_simple(file_path)
    detect_and_set_project_scope

    importer = Dradis::Plugins::Nexpose::Simple::Importer.new(task_options)
    importer.import(file: file_path)
  end

  private

  def process_upload(importer, file_path)
    require 'config/environment'

    unless File.exists?(file_path)
      $stderr.puts "** the file [#{file_path}] does not exist"
      exit -1
    end

    importer.import(file: file_path)
  end
end
