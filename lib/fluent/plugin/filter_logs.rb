# frozen_string_literal: true

#
# Copyright 2020- Camille Meulien
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

require 'json'
require 'date'
require 'logfmt'
require 'fluent/plugin/filter'

module Fluent
  module Plugin
    class LogsFilter < Filter
      Fluent::Plugin.register_filter('logs', self)
      REGEXPS_LOGS = [
        [/^(?<upstream_ip>\S+) - - \[\S+ \+\d{4}\] "(?<message>\S+ \S+ [^"]+)" (?<status_code>\d{3}) (?<content_size>\d+|-) "(?<referer>.*?)" "(?<user_agent>[^"]+)" "(?<user_ip>[^"]+)"$/],
        [/^\[[^\]]+\] (?<upstream_ip>\S+) - [^ ]+ \[[^\]]+\] "(?<message>\S+ \S+ [^"]+)" (?<status_code>\d{3}) (?<content_size>\d+|-) "(?<referer>.*?)" "(?<user_agent>[^"]+)"/],
        [/^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S+ \[(?<level>[^\]]+)\] (?<message>.*)/],
        [/^.. \[[^\]]+?( \#\d+)?\] +(?<level>\S+) -- : (?<message>.*)$/],
        [/^(?<level>[DINWECA])\d{4} \d{2}:\d{2}:\d{2}\.\d+ +(?<message>.*)$/],
        [%r{^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC (?<message>(?:\S+ ){1,2}#\d+ (?<level>\S+) import (?<peers>\d+)/(?<peers_max>\d+) peers? .*)$},
         lambda do |r|
           ratio = r['peers'].to_f / r['peers_max'].to_f
           l = ratio <= 0.1 ? 'ERROR' : ratio <= 0.2 ? 'WARN' : 'INFO'
           return { 'level' => l }
         end],
        [/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC (?<message>(?:\S+ ){1,2}#\d+ (?<level>\S+) .*)$/],
        [/^ranger_\S+: \d+$/, { 'level' => 'INFO' }]
      ].freeze

      def ow_parse_logs(text)
        return {} unless text

        if text[0] == '{'
          begin
            return JSON.parse(text)
          rescue JSON::ParserError
            # byebug
          end
        end

        REGEXPS_LOGS.each do |r, additional|
          m = text.match(r)
          next unless m

          record = m.named_captures
          if additional
            record.merge!(additional) if additional.is_a?(Hash)
            record.merge!(additional.call(record)) if additional.is_a?(Proc)
          end
          return record
        end

        if text.match(/^(?:[a-zA-Z0-9]+=(?:\"[^"]*\"|\S*) ?)+/)
          return Logfmt.parse(text)
        end

        {}
      end

      RENAME_MAP = [
        %w[msg message],
        %w[lvl level]
      ].freeze

      FORMATTERS = [
        ['level', lambda do |value|
          case value
          when /^warning$/i then return 'WARN'
          when /^note$/i then return 'INFO'
          when 'D' then return 'DEBUG'
          when 'I' then return 'INFO'
          when 'N' then return 'NOTICE'
          when 'W' then return 'WARN'
          when 'E' then return 'ERROR'
          when 'C' then return 'CRITICAL'
          when 'A' then return 'ALERT'
          end
          value.upcase
        end]
      ].freeze

      def ow_post_process(record)
        text = record['log']
        record.delete('log')

        if record['data']
          record['status_code'] = record['data']['status']
          record['level'] = 'DEBUG'
          record['message'] = JSON.dump(record.delete('data'))
        end

        if record['status_code']
          record['status_code'] = record['status_code'].to_i
        end

        RENAME_MAP.each do |src, dst|
          if record[src] && record[dst].nil?
            record[dst] = record[src]
            record.delete(src)
          end
        end

        FORMATTERS.each do |k, formatter|
          record[k] = formatter.call(record[k]) if record[k]
        end

        record['message'] ||= text
        record
      end

      def filter(_tag, _time, record)
        log.trace { "filter_logs: (#{record.class}) #{record.inspect}" }
        record = record.merge(ow_parse_logs(record['log']))
        ow_post_process(record)
      end
    end
  end
end
