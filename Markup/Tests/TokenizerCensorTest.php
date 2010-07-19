<?php

namespace s9e\Toolkit\Markup;

include_once __DIR__ . '/../ConfigBuilder.php';
include_once __DIR__ . '/../Parser.php';

class TokenizerCensorTest extends \PHPUnit_Framework_TestCase
{
	public function testExactCensoring()
	{
		$config   = $this->getConfig(array('apple' => 'pear'));

		$text     = 'You dirty apple';
		$actual   = parser::getCensorTags($text, $config);
		$expected = array(
			'tags' => array(
				array(
					'pos'    => 10,
                    'name'   => 'CENSOR',
                    'len'    => 5,
                    'params' => array('replacement' => 'pear')
				)
			),
			'msgs' => array()
		);

		$this->assertKindaEquals($expected, $actual);
	}

	public function testExactCensoringWithNoReplacement()
	{
		$config   = $this->getConfig(array('apple' => null));

		$text     = 'You dirty apple';
		$actual   = parser::getCensorTags($text, $config);
		$expected = array(
			'tags' => array(
				array(
					'pos'    => 10,
                    'name'   => 'CENSOR',
                    'len'    => 5
				)
			),
			'msgs' => array()
		);

		$this->assertKindaEquals($expected, $actual);
	}

	public function testExactCensorDoesNotApplyToPartialMatch()
	{
		$config   = $this->getConfig(array('apple' => 'pear'));

		$text     = 'You dirty applepie';
		$actual   = parser::getCensorTags($text, $config);
		$expected = array(
			'tags' => array(),
			'msgs' => array()
		);

		$this->assertKindaEquals($expected, $actual);
	}

	public function testPartialCensorAppliesToPartialMatch()
	{
		$config   = $this->getConfig(array('apple*' => 'pear'));

		$text     = 'You dirty applepie';
		$actual   = parser::getCensorTags($text, $config);
		$expected = array(
			'tags' => array(
				array(
					'pos'    => 10,
                    'name'   => 'CENSOR',
                    'len'    => 8,
                    'params' => array('replacement' => 'pear')
				)
			),
			'msgs' => array()
		);

		$this->assertKindaEquals($expected, $actual);
	}

	public function testCensoredUnicodeWordAppliesToUnicodeText()
	{
		$config   = $this->getConfig(array("pok\xC3\xA9*" => null));

		$text     = "You dirty Pok\xC3\xA9man";
		$actual   = parser::getCensorTags($text, $config);
		$expected = array(
			'tags' => array(
				array(
					'pos'    => 10,
                    'name'   => 'CENSOR',
					// length in bytes
                    'len'    => 8
				)
			),
			'msgs' => array()
		);

		$this->assertKindaEquals($expected, $actual);
	}

	public function testCensoredASCIIWordAppliesToUnicodeText()
	{
		$config   = $this->getConfig(array("pok*" => null));

		$text     = "You dirty Pok\xC3\xA9man";
		$actual   = parser::getCensorTags($text, $config);
		$expected = array(
			'tags' => array(
				array(
					'pos'    => 10,
                    'name'   => 'CENSOR',
					// length in bytes
                    'len'    => 8
				)
			),
			'msgs' => array()
		);

		$this->assertKindaEquals($expected, $actual);
	}

	public function testTokenizerLimitIsRespected()
	{
		$config = $this->getConfig(array('apple*' => null, 'banana' => null));
		$config['limit_action'] = 'ignore';

		$text = str_repeat('apple banana ', 6);
		$ret  = parser::getCensorTags($text, $config);

		$this->assertSame(10, count($ret['tags']));
	}

	/**
	* @expectedException Exception
	*/
	public function testTokenizerLimitExceededWithActionAbortThrowsAnException()
	{
		$config = $this->getConfig(array('apple*' => null, 'banana' => null));
		$config['limit_action'] = 'abort';

		$text = str_repeat('apple banana ', 6);
		$ret  = parser::getCensorTags($text, $config);
	}

	protected function getConfig($words)
	{
		$cb = new ConfigBuilder;

		$cb->addBBCode('censor');
		$cb->addBBCodeParam('censor', 'replacement', 'text', false);

		$cb->setCensorOption('bbcode', 'censor');
		$cb->setCensorOption('param', 'replacement');
		$cb->setCensorOption('limit', 10);

		foreach ($words as $word => $replacement)
		{
			$cb->addCensor($word, $replacement);
		}

		return $cb->getCensorConfig();
	}

	protected function assertKindaEquals($expected, $actual)
	{
		foreach ($expected as $type => $content)
		{
			$this->assertArrayHasKey($type, $actual);

			if (count($expected[$type]) !== count($actual[$type]))
			{
				$this->assertEquals($expected[$type], $actual[$type]);
			}

			switch ($type)
			{
				case 'msgs':
					$this->assertKindaEquals($expected['msgs'], $actual['msgs']);
					break;

				case 'tags':
				case 'error':
				case 'warning':
				case 'debug':
					foreach ($content as $k => $v)
					{
						$this->assertEquals(
							$v,
							array_intersect_key($actual[$type][$k], $v)
						);
					}
					break;

				default:
					$this->fail('Unknown key');
			}
		}
	}
}