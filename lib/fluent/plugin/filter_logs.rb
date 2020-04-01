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

require "fluent/plugin/filter"

module Fluent
  module Plugin
    class LogsFilter < Filter
      Fluent::Plugin.register_filter("logs", self)

      def filter(tag, time, record)
        logger.info "filter tag: #{tag.inspect}"
        logger.info "filter time: #{time.inspect}"
        logger.info "filter record: #{record.inspect}"
        record
      end
    end
  end
end