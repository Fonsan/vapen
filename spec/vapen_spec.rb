require 'spec_helper'
module Vapen
  module SCUtil
    describe ReachabilityReader do
      let(:statuses_array) { [] }
      subject { ReachabilityReader.new(&statuses_array.method(:<<)) }

      def feed_init
        subject.feed " 0: direct\n   <SCNetworkReachability 0x7f8afbc0d890 [0x7fff7c331ed0]> {name = vpn.byburt.com}\n"
        subject.feed "Reachable\n"
        subject.feed "\n 1: start\n   <SCNetworkReachability 0x7f8afbd132a0 [0x7fff7c331ed0]> {name = vpn.byburt.com}\n\n"
        subject.feed " 2: on runloop\n"
        subject.feed "   <SCNetworkReachability 0x7f8afbd132a0 [0x7fff7c331ed0]> {name = vpn.byburt.com (server query active), [46], flags = 0x80000002, if_index = 4}\n"
        subject.feed "Reachable\n\n"
      end

      def first_status
        subject.feed "\n*** 14:59:41.820\n\n 3: callback w/flags=0x00000002 (info=\"by name\")\n"
        subject.feed "    <SCNetworkReachability 0x7f8afbd132a0 [0x7fff7c331ed0]> {name = vpn.byburt.com (54.220.45.76, 54.73.141.160), [46], flags = 0x00000002, if_index = 4}\nReachable\n\n"
      end

      def disconnect
        subject.feed "\n*** 14:59:51.971\n\n 4: callback w/flags=0x00000007 (info=\"by name\")\n    <SCNetworkReachability 0x7f8afbd132a0 [0x7fff7c331ed0]> {name = vpn.byburt.com (nodename nor servname provided, or not known), [46], flags = 0x00000007, if_index = 0}\nReachable,Transient Connection,Connection Required\n\n"
      end

      def network_connect
        subject.feed "\n*** 14:59:57.402\n\n 5: callback w/flags=0x00000000 (info=\"by name\")\n    <SCNetworkReachability 0x7f8afbd132a0 [0x7fff7c331ed0]> {name = vpn.byburt.com (DNS query active), [], flags = 0x00000000, if_index = 0}\nNot Reachable\n\n"
      end

      def reachable_again
        subject.feed "\n*** 14:59:57.540\n\n 6: callback w/flags=0x00000002 (info=\"by name\")\n"
        subject.feed "    <SCNetworkReachability 0x7f8afbd132a0 [0x7fff7c331ed0]> {name = vpn.byburt.com (54.220.45.76, 54.73.141.160), [46], flags = 0x00000002, if_index = 4}\nReachable\n\n"
      end

      it 'discards init' do
        feed_init
        expect(statuses_array).to be_empty
      end

      it 'reads first status' do
        feed_init
        first_status
        expect(statuses_array).to eq([['Reachable']])
      end

      it 'handles being disconnected' do
        feed_init
        first_status
        disconnect
        expect(statuses_array.last).to eq(["Reachable", "Transient Connection", "Connection Required"])
      end

      it 'handles being reconnected again' do
        feed_init
        first_status
        disconnect
        network_connect
        expect(statuses_array.last).to eq(['Not Reachable'])
      end

      it 'handles being reachable again' do
        feed_init
        first_status
        disconnect
        network_connect
        reachable_again
        expect(statuses_array.last).to eq(['Reachable'])
      end
    end
  end
end