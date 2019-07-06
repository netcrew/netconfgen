require 'minitest/autorun'

require 'netconfgen'

class BlockEngine < Minitest::Test

  def test_block_loading

    br = NetConfGen::BlockEngine.new('test/data')
    block = br.load('file1')
    assert_equal block.code, "! this is a code module\n"
  end

  def test_block_variables

    br = NetConfGen::BlockEngine.new('test/data')

    br.set('foo', 1)
    br.set('bar', 'hello')
    block = br.load('variables')
    assert_equal block.render, "foo: 1\nbar: hello\n"
  end


  def test_recursive_block_rendering
    br = NetConfGen::BlockEngine.new('test/data')
    block = br.load('file2')

    assert_equal block.render,
%{! main
! this is a code module

! main again
}

  end
end