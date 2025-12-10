SELECT
  `b`.`emailaddress` AS `email`,
  `b`.`first_name` AS `nombre`,
  TRIM(
    CASE
      WHEN TRIM(`b`.`last_name`) LIKE '% %' THEN SUBSTRING_INDEX( TRIM(`b`.`last_name`), ' ', CHAR_LENGTH(TRIM(`b`.`last_name`)) - CHAR_LENGTH(REPLACE(TRIM(`b`.`last_name`), ' ', '')) )
      ELSE TRIM(`b`.`last_name`)
  END
    ) AS `apellido1`,
  TRIM(
    CASE
      WHEN TRIM(`b`.`last_name`) LIKE '% %' THEN SUBSTRING_INDEX(TRIM(`b`.`last_name`), ' ', -1)
      ELSE ''
  END
    ) AS `apellido2`
FROM (
  SELECT
    `ils`.`emailaddress`,
    COALESCE(MAX(CASE
          WHEN `cf`.`name` = 'First Name' THEN `sd`.`data`
      END
        ), '') AS `first_name`,
    COALESCE(MAX(CASE
          WHEN `cf`.`name` = 'Last Name' THEN `sd`.`data`
      END
        ), '') AS `last_name`
  FROM
    `gr_wordpress`.`insp_list_subscribers` AS `ils`
  LEFT JOIN
    `gr_wordpress`.`insp_subscribers_data` AS `sd`
  ON
    `sd`.`subscriberid` = `ils`.`subscriberid`
  LEFT JOIN
    `gr_wordpress`.`insp_customfields` AS `cf`
  ON
    `cf`.`fieldid` = `sd`.`fieldid`
  WHERE
    `ils`.`confirmed` = 1
    AND `ils`.`unsubscribeconfirmed` = 0
    AND `ils`.`listid` = 63
  GROUP BY
    `ils`.`emailaddress` ) AS `b`;