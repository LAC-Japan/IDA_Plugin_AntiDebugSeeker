# IDA_Plugin_AntiDebugSeeker

## Concept

This tool was created to assist those who are new to malware analysis or are not yet familiar with anti-debugging techniques. 
Through this tool, users can automatically extract potential anti-debugging methods used by malware, making it easier for analysts to take appropriate action.

## Introduction

The main functionalities of this plugin are as follows:

- Extraction of APIs that are potentially being used for anti-debugging by the malware.
- In addition to APIs, extraction of anti-debugging techniques based on key phrases that serve as triggers, as some anti-debugging methods cannot be comprehensively identified by API calls alone.

For packed samples, running this plugin after unpacking and fixing the Import Address Table is more effective.

## Installation

Place the following three files under the plugin directory of IDA :

anti_debug.config (A file containing rules for detecting anti-debugging techniques)
anti_debug_techniques_descriptions.json (A file containing descriptions of the detected rules)
AntiDebugSeeker.py (The anti-debugging detection program)

## Usage

## Support Functions

## About anti_debug.config

## List of detectable anti-debugging techniques


