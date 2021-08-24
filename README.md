# IntcodeGhidra

Implements a Ghidra processor extension for the imaginary [Intcode CPU/abstract machine from Advent of Code 2019](https://adventofcode.com/2019/day/2). Compatible with Ghidra 10.0.1 and later. Just for fun, unpolished, and not fully functional. Use/enjoy at your own risk!

I finished this a while ago and forgot about it until now, then decided I may as well tidy it up and publish it 🤷‍♂️.

This also comes with a simple loader for comma-separated numbers formatted like the original Advent of Code examples. However, I quickly realized that it doesn't work very well with many of the examples, since they make heavy use of some wacky Intcode features that Ghidra doesn't support (memory address reuse/repurposing, infinite memory space, etc., and **especially** self-modifying code).

The hardest challenge of this project: it was a REAL pain in the rear to get the opcodes and addresses correct since they're base-10 instead of binary (see `gen_sla.py`), but it sure was rewarding once it finally "worked". 😄
