module Dradis::Plugins::Nexpose
  module Mapping
    DEFAULT_MAPPING = {
      full_evidence: {
        'ID' => '{{ nexpose[evidence.id] }}',
        'Status' => '{{ nexpose[evidence.status] }}',
        'Content' => '{{ nexpose[evidence.content] }}'
      },
      full_node: {
        'Title' => '{{ nexpose[node.address] }}',
        'Hostname' => '{{ nexpose[node.site_name] }}',
        'Details' => "Status: {{ nexpose[node.status] }}\n
                      Device id: {{ nexpose[node.device_id] }}\n
                      HW address: {{ nexpose[node.hardware_address] }}",
        'Names' => '{{ nexpose[node.names] }}',
        'Software' => '{{ nexpose[node.software] }}'
      },
      full_scan: {
        'Title' => '{{ nexpose[scan.name] }} ({{ nexpose[scan.scan_id] }})',
        'Timing' => "Start time: {{ nexpose[scan.start_time] }}\n
                    End time: {{ nexpose[scan.end_time] }}",
        'Status' => '{{ nexpose[scan.status] }}'
      },
      full_service: {
        'Title' => 'Service name: {{ nexpose[service.name] }}',
        'Fingerprinting' => '{{ nexpose[service.fingerprints] }}',
        'Configuration' => '{{ nexpose[service.configurations] }}',
        'Tests' => '{{ nexpose[service.tests] }}'
      },
      full_vulnerability: {
        'Title' => '{{ nexpose[vulnerability.title] }}',
        'Nexpose Id' => '{{ nexpose[vulnerability.nexpose_id] }}',
        'Severity' => '{{ nexpose[vulnerability.severity] }}',
        'PCI Severity' => '{{ nexpose[vulnerability.pci_severity] }}',
        'CVSS Score' => '{{ nexpose[vulnerability.cvss_score] }}',
        'CVSS Vector' => '{{ nexpose[vulnerability.cvss_vector] }}',
        'Published' => '{{ nexpose[vulnerability.published] }}',
        'Description' => '{{ nexpose[vulnerability.description] }}',
        'Solution' => '{{ nexpose[vulnerability.solution] }}',
        'References' => '{{ nexpose[vulnerability.references] }}',
        'Tags' => '{{ nexpose[vulnerability.tags] }}'
      },
      simple_port: {
        'Id' => '{{ nexpose[port.id] }}',
        'References' => '{{ nexpose[port.finding] }}'
      }
    }.freeze

    SOURCE_FIELDS = {
      full_evidence: [
        'evidence.id',
        'evidence.status',
        'evidence.content',
        'evidence.port',
        'evidence.protocol'
      ],
      full_node: [
        'node.address',
        'node.device_id',
        'node.fingerprints',
        'node.hardware_address',
        'node.names',
        'node.tests',
        'node.risk_score',
        'node.site_name',
        'node.status',
        'node.software'
      ],
      full_scan: [
        'scan.end_time',
        'scan.name',
        'scan.scan_id',
        'scan.start_time',
        'scan.status'
      ],
      full_service: [
        'service.configurations',
        'service.fingerprints',
        'service.name',
        'service.tests'
      ],
      full_vulnerability: [
        'vulnerability.added',
        'vulnerability.cvss_score',
        'vulnerability.cvss_vector',
        'vulnerability.description',
        'vulnerability.modified',
        'vulnerability.nexpose_id',
        'vulnerability.pci_severity',
        'vulnerability.published',
        'vulnerability.risk_score',
        'vulnerability.references',
        'vulnerability.severity',
        'vulnerability.solution',
        'vulnerability.tags',
        'vulnerability.title'
      ],
      simple_port: [
        'port.finding',
        'port.id'
      ]
    }.freeze
  end
end
