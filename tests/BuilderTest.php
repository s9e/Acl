<?php

namespace s9e\TextFormatter\Tests;

use PHPUnit_Framework_TestCase;
use s9e\Acl\Builder;

/**
* @covers s9e\Acl\Builder
*/
class BuilderTest extends PHPUnit_Framework_TestCase
{
	public function testDenyOverridesAllow()
	{
		$acl->deny('publish');
		$acl->allow('publish');
	}
}