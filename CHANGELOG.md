vX.X.X (XXX 2023)
  - Use the details in <os> as the OS node property

v4.10.0 (September 2023)
  - Update gemspec links

v4.9.0 (June 2023)
  - Parse inline code, not just code blocks
  - Wrap ciphers in the `ssl-weak-message-authentication-code-algorithms` finding

v4.8.0 (April 2023)
  - No changes

v4.7.0 (February 2023)
  - No changes

v4.6.0 (November 2022)
  - No changes

v4.5.0 (August 2022)
  - No changes

v4.4.0 (June 2022)
  - Registers template mappings locally

v4.3.0 (April 2022)
  - Update HTML tag cleanup to cover `UnorderedList` tags without spaces and double `Paragraph preformat` tags

v4.2.0 (February 2022)
  - Pull the Hostname Node property from the `name` rather than `site-name` tag

v4.1.0 (November 2021)
  - Update HTML tag cleanup to better cover `UnorderedList` and `URLLink` tags in the solution field

v4.0.0 (July 2021)
  - Expand coverage for cipher wrapping to ssl-anon-ciphers and ssl-only-weak-ciphers
  - Update HTML tag cleanup

v3.22.0 (April 2021)
  - No changes

v3.21.0 (February 2021)
  - No changes

v3.20.0 (December 2020)
  - Expand coverage for cipher wrapping

v3.19.0 (September 2020)
  - No changes

v3.18.0 (July 2020)
  - No changes

v3.17.0 (May 2020)
  - Expand coverage for cipher wrapping

v3.16.0 (February 2020)
  - No changes

v3.15.0 (November 2019)
  - Wrap ciphers in code blocks

v3.14.0 (August 2019)
  - Add risk-score attribute to nodes

v3.13.0 (June 2019)
  - No changes

v3.12.0 (March 2019)
  - No changes

v3.11.0 (November 2018)
  - No changes

v3.10.1 (October 2018)
  - Fix usage of set_property(:services) to use set_service

v3.10.0 (August 2018)
  - Create `hostname` and `os` Node properties (if present)
  - Improve parsing of `<ListItem>` tags
  - Import `vulnerability.tags` field as expected
  - Import `<Paragraph preformat="true">` tags as code blocks
  - Import `<URLLink>` tags as textile links
  - Resolve duplicate content in nested `<Paragraph>` tags

v3.9.0 (January 2018)
  - No changes

v3.8.0 (September 2017)
  - No changes

v3.7.0 (July 2017)
  - Add full evidence template for exporting evidences
  - Fix issue resulting in Evidence with null content

v3.6.0 (March 2017)
  - No changes
