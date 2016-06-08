#!/usr/bin/env ruby

$: << File.expand_path('../../lib', __FILE__)
require 'vapen'

abort "Usage: vapen hostname" unless hostname = ARGV.first

Vapen::VPNAutoConnector.new(hostname).run.join