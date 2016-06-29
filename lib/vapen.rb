require 'open3'
require 'shellwords'

module Vapen
  module SCUtil
    class STDOUTProcessReader
      MAXLEN = 1024
      attr_reader :thread
      def initialize(*args, &block)
        @args = args
        @block = block
      end

      def run
        Thread.abort_on_exception = true
        @thread = Thread.start do
          Open3.popen3(*@args) do |_, stdout, _, _|
            pipes = [stdout]
            loop do
              IO.select(pipes).first.each do |io|
                begin
                  @block.call io.read_nonblock(MAXLEN)
                rescue EOFError
                  break
                end
              end
            end
          end
        end
      end
    end

    class ReachabilityReader
      def initialize(&block)
        @block = block
        @buf = ""
      end

      def feed(str)
        @buf << str
        matches = @buf.scan(/(.*?\*\*\*.+?\n\n.+?\}\n)(.+?)(\n\n)/m)
        matches.each do |_, status_str, _|
          @block.call(status_str.split(','))
        end
        if matches.any?
          offset = matches.flatten.map(&:size).reduce(0,:+) - 1
          @buf = @buf[offset..-1]
        end
      end
    end

    class HostStatusWatcher
      def initialize(hostname, &block)
        @hostname = hostname
        @reachability_reader = ReachabilityReader.new(&block)
      end

      def run
        STDOUTProcessReader.new('scutil', '-W', '-r', @hostname, &@reachability_reader.method(:feed)).run
      end
    end

    class VPNAutoConnector
      def initialize(hostname)
        @hostname = hostname
      end

      def run
        HostStatusWatcher.new(@hostname) do |statuses|
          if statuses == ['Reachable']
            vpns_matching_hostname.each do |name|
              connect(name)
            end
          end
        end.run
      end

      private

      def disconnected_vpns
        `scutil --nc list`.lines.grep(/\(Disconnected\)/).map {|line| line.match(/"(.+?)"/)[1] }
      end

      def vpns_matching_hostname
        disconnected_vpns.select do |name|
          info = `scutil --nc show #{name.shellescape}`
          info.match(Regexp.new("RemoteAddress : #{Regexp.escape(@hostname)}"))
        end
      end

      def connect(name)
        system("scutil", "--nc", "start", name)
      end
    end
  end
  VPNAutoConnector = SCUtil::VPNAutoConnector
end

