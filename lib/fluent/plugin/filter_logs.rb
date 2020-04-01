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
        /^(?<upstream_ip>\S+) - - \[(?<time>\S+ \+\d{4})\] "(?<message>\S+ \S+ [^"]+)" (?<status_code>\d{3}) (?<content_size>\d+|-) "(?<referer>.*?)" "(?<user_agent>[^"]+)" "(?<user_ip>[^"]+)"$/,
        /^\[[^\]]+\] (?<upstream_ip>\S+) - [^ ]+ \[(?<time>[^\]]+)\] "(?<message>\S+ \S+ [^"]+)" (?<status_code>\d{3}) (?<content_size>\d+|-) "(?<referer>.*?)" "(?<user_agent>[^"]+)"/,
        /^(?<time>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S+) \[(?<level>[^\]]+)\] (?<message>.*)/,
        /^.. \[(?<time>[^\]]+?)( \#\d+)?\] +(?<level>\S+) -- : (?<message>.*)$/
      ].freeze

      REGEXPS_DATES = [
        [/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}/, '%FT%T.%L'],
        [/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}/, '%FT%T.%L%z'],
        [/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/, '%FT%T%z'],
        [/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}/, '%F %T.%L'],
        [/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/, '%F %T'],
        [%r{\d{2}/[a-zA-Z]+/\d{4}:\d{2}:\d{2}:\d{2}}, '%d/%b/%Y:%H:%M:%S %z']
      ].freeze

      def ow_parse_time(str)
        return nil if str.nil?

        REGEXPS_DATES.each do |pattern, format|
          if str.match(pattern)
            return DateTime.strptime(str, format).to_time.to_i
          end
        end
        DateTime.strptime(str).to_time.to_i
      rescue ArgumentError => e
        log.warn "#{e}, time str: #{str}"
      end

      def ow_parse_logs(text)
        if text[0] == '{'
          begin
            return JSON.parse(text)
          rescue JSON::ParserError
            # byebug
          end
        end

        REGEXPS_LOGS.each do |r|
          m = text.match(r)
          next unless m

          return m.named_captures
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

      def ow_post_process(record)
        text = record['log']
        record.delete('log')

        RENAME_MAP.each do |src, dst|
          if record[src] && record[dst].nil?
            record[dst] = record[src]
            record.delete(src)
          end
        end
        record['message'] ||= text
        return record
      end

      def filter(_tag, _time, record)
        log.trace { "filter_logs: (#{record.class}) #{record.inspect}" }
        if record['log']
          record = record.merge(ow_parse_logs(record['log']))
          record = ow_post_process(record)

          if record['time']
            record['timestamp'] = ow_parse_time(record['time'])
            record.delete('time')
          end
        end
        record
      end
    end
  end
end
