<?php
include_once 'Base.php';

class Polynomial extends DecayingModelBase
{
    function __construct() {
        $this->Attribute = ClassRegistry::init("Attribute");
        $this->description = __('The implementation of the decaying formula from the paper `An indicator scoring method for MISP platforms`.');
    }

    public function computeScore($model, $attribute, $base_score, $elapsed_time)
    {
        if ($elapsed_time < 0) {
            return 0;
        }
        $decay_speed = $model['DecayingModel']['parameters']['decay_speed'];
        $lifetime = $model['DecayingModel']['parameters']['lifetime']*24*60*60;
        $score = $base_score * (1 - pow($elapsed_time / $lifetime, 1 / $decay_speed));
        return $score < 0 ? 0 : $score;
    }

    public function isDecayed($model, $attribute, $score)
    {
        $threshold = $model["DecayingModel"]["parameters"]["threshold"];

		$this->Sighting = ClassRegistry::init("Sighting");
		$all_sightings = $this->Sighting->listSightings(
			$_SESSION["Auth"]["User"],
			$attribute["id"],
			"attribute",
			false,
			2,
			true
		);
		if (!empty($all_sightings)) {
			$last_sighting_timestamp =
				$all_sightings[0]["Sighting"]["date_sighting"];
			$decayed = $last_sighting_timestamp < time();
		} else {
			$decayed = $threshold > $score;
		}

		if ($attribute["to_ids"] == $decayed) {
			$attribute["to_ids"] = !$decayed;
			$this->Attribute->editAttribute(
				$attribute,
				["Event" => ["id" => $attribute["event_id"]]],
				$_SESSION["Auth"]["User"],
				$attribute["object_id"],
				false,
				true
			);
		}
		return $threshold > $score;
    }
}
