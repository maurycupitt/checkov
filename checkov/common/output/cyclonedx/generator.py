#
# Copyright 2019-Present Sonatype Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import logging
import json
from collections import defaultdict

from lxml import etree

XMLNS = "http://cyclonedx.org/schema/bom/1.1"
XMLNSV = "http://cyclonedx.org/schema/ext/vulnerability/1.0"

NSMAP = {"v": XMLNSV}


def code_line_string(code_block):
  string_block = ''
  last_line_number, _ = code_block[-1]

  for (line_num, line) in code_block:
    spaces = '    ' * (len(str(last_line_number)) - len(str(line_num)))
    string_block += str(line_num) + ' | ' + spaces + line
  return string_block


class CycloneDxSbomGenerator():
    """CycloneDx11Generator is responsible for taking identifiers
  and vulnerabilities and turning them into a CycloneDX 1.1 SBOM"""

    def __init__(self):
        self._log = logging.getLogger('checkov')
        self.__xml = []

    def create_and_return_sbom(self, records) -> (list):
        """create_and_return_sbom is responsible for taking results in
    CoordinateResults form and turning them into a valid CycloneDX SBOM"""
        sbom = self.create_xml_from_checkov(records)
        return sbom

    @staticmethod
    def sbom_to_string(sbom: etree.Element) -> (bytes):
        """sbom_to_string is responsible for turning an sbom into a string"""
        return etree.tostring(sbom, encoding="UTF-8")

    def create_xml_from_checkov(self, report: dict) -> (etree.Element):
        self.__create_root()
        components = etree.Element('components')
        by_resource = defaultdict(list)
        # Aggregate records by resource
        for record in report.failed_checks:
            by_resource[record.resource].append(record)

        for resource, checks in by_resource.items():
            purl_txt = "pkg:{0}/{1}@current".format(report.check_type, checks[0].resource)
            component = etree.Element('component', {"type": "library", "bom-ref": purl_txt})
            publisher = etree.SubElement(component, 'publisher')
            publisher.text = 'checkov'
            group = etree.SubElement(component, 'group')
            group.text = checks[0].file_path
            name = etree.SubElement(component, 'name')
            name.text = resource
            version = etree.SubElement(component, 'version')
            version.text = "current"
            purl = etree.SubElement(component, 'purl')
            purl.text = purl_txt
            # vulnerabilities
            vulnerabilities = etree.Element("{%s}vulnerabilities" % XMLNSV, nsmap=NSMAP)
            for check in checks:
                vulnerability = etree.Element("{%s}vulnerability" % XMLNSV, {"ref": purl_txt})
                # vulnerability = etree.Element("{%s}vulnerability" % XMLNSV)
                _id = etree.SubElement(vulnerability, "{%s}id" % XMLNSV)
                _id.text = check.check_id
                source = etree.Element("{%s}source" % XMLNSV, {"name": "bridgecrew.io"})
                url = etree.SubElement(source, "{%s}url" % XMLNSV)
                url.text = check.guideline
                vulnerability.append(source)
                ratings = etree.Element("{%s}ratings" % XMLNSV)
                rating = etree.SubElement(ratings, "{%s}rating" % XMLNSV)
                score = etree.SubElement(rating, "{%s}score" % XMLNSV)
                base = etree.SubElement(score, "{%s}base" % XMLNSV)
                base.text = "9.0"
                # vector = etree.SubElement(rating, "{%s}vector" % XMLNSV)
                # vector.text = vuln.get_cvss_vector()
                vulnerability.append(ratings)
                description = etree.SubElement(vulnerability, "{%s}description" % XMLNSV)

                desc_text = "### " + check.check_name + "\n\n" + \
                            "* FAILED for Resource: `" + check.resource + "`\n" + \
                            "* Check Class: `" + check.check_class + "`\n" + \
                            "* File: `" + check.file_path + "`\n\n" + \
                            "##### Code Block: \n\n" + \
                            '``` ' + code_line_string(check.code_block) + ' ``` '

                if check.evaluations is not None and len(check.evaluations) > 0:
                    desc_text += " \n\n##### Evaluations: \n```\n" + (
                        json.dumps(check.evaluations, sort_keys=False, indent=4, separators=(',', ': '))) + "\n```"

                description.text = desc_text
                if check.guideline is not None:
                    advisories = etree.Element("{%s}advisories" % XMLNSV)
                    advisory = etree.SubElement(advisories, "{%s}advisory" % XMLNSV)
                    advisory.text = check.guideline
                    vulnerability.append(advisories)

                vulnerabilities.append(vulnerability)
            component.append(vulnerabilities)
            components.append(component)
        self.__xml.append(components)
        return self.__xml

    def __create_root(self):
        self.__xml = etree.Element('bom', {"xmlns": XMLNS, "version": "1"}, nsmap=NSMAP)
