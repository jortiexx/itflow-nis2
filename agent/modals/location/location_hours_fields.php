<?php
/*
 * Opening hours per day for the location add/edit modals.
 * Expects $location_hours_raw (unescaped value of locations.location_hours, '' for a new location).
 * Posts hours_form, hours_open[i], hours_from[i], hours_to[i] (i = 0..6, maandag first); agent/post/location_model.php builds the stored string.
 */

$hours_raw = (string) ($location_hours_raw ?? '');
$hours_week = parseLocationHours($hours_raw);
$hours_legacy = $hours_week === null ? $hours_raw : '';
if ($hours_week === null) {
    $hours_week = [];
}
$hours_box_id = 'locHours' . bin2hex(random_bytes(4));
$hours_day_names = ['Maandag', 'Dinsdag', 'Woensdag', 'Donderdag', 'Vrijdag', 'Zaterdag', 'Zondag'];
?>
<div class="form-group" id="<?php echo $hours_box_id; ?>">
    <label><i class="fa fa-fw fa-clock mr-1"></i>Openingstijden</label>
    <input type="hidden" name="hours_form" value="1">

    <?php if ($hours_legacy !== '') { ?>
        <div class="alert alert-warning py-2 small">
            Huidige tekst kan niet per dag worden gelezen en wordt bij opslaan vervangen:<br>
            <strong><?php echo nullable_htmlentities($hours_legacy); ?></strong>
        </div>
    <?php } ?>

    <table class="table table-sm table-borderless mb-1">
        <tbody>
        <?php for ($i = 0; $i < 7; $i++) {
            $d = $hours_week[$i] ?? null;
            $is_open = is_array($d);
            $from = $is_open ? $d['from'] : '08:00';
            $to = $is_open ? $d['to'] : '18:00';
            ?>
            <tr class="hours-row" data-day="<?php echo $i; ?>">
                <td class="align-middle pl-0" style="width: 30%;">
                    <div class="custom-control custom-checkbox">
                        <input type="checkbox" class="custom-control-input hours-open" id="<?php echo "{$hours_box_id}_open$i"; ?>" name="hours_open[<?php echo $i; ?>]" value="1" <?php if ($is_open) { echo 'checked'; } ?>>
                        <label class="custom-control-label" for="<?php echo "{$hours_box_id}_open$i"; ?>"><?php echo $hours_day_names[$i]; ?></label>
                    </div>
                </td>
                <td style="width: 25%;"><input type="time" class="form-control form-control-sm hours-from" name="hours_from[<?php echo $i; ?>]" value="<?php echo $from; ?>" step="900" <?php if (!$is_open) { echo 'disabled'; } ?>></td>
                <td style="width: 25%;"><input type="time" class="form-control form-control-sm hours-to" name="hours_to[<?php echo $i; ?>]" value="<?php echo $to; ?>" step="900" <?php if (!$is_open) { echo 'disabled'; } ?>></td>
                <td class="align-middle small text-nowrap"><span class="hours-note"></span></td>
            </tr>
        <?php } ?>
        </tbody>
    </table>

    <div class="btn-group btn-group-sm">
        <button type="button" class="btn btn-outline-secondary hours-office">Kantoortijden</button>
        <button type="button" class="btn btn-outline-secondary hours-copy">Kopieer naar alle dagen</button>
        <button type="button" class="btn btn-outline-secondary hours-clear">Leegmaken</button>
    </div>
    <small class="form-text text-muted">Niets aangevinkt = standaard ma-vr 08:00-18:00. Eindtijd gelijk aan of vóór begintijd = volgende dag (00:00-00:00 = hele dag open).</small>
</div>

<script>
(function () {
    var $box = $('#<?php echo $hours_box_id; ?>');
    var lastRow = 0;

    function refresh($row) {
        var open = $row.find('.hours-open').is(':checked');
        var from = $row.find('.hours-from').val();
        var to = $row.find('.hours-to').val();
        $row.find('.hours-from, .hours-to').prop('disabled', !open);
        var note = '';
        if (open && from && to) {
            if (from === '00:00' && to === '00:00') {
                note = '<span class="text-success">hele dag</span>';
            } else if (to === from) {
                note = '<span class="text-danger">ongeldig</span>';
            } else if (to < from) {
                note = '<span class="text-info">volgende dag</span>';
            }
        } else if (!open) {
            note = '<span class="text-muted">dicht</span>';
        }
        $row.find('.hours-note').html(note);
    }

    function setRow($row, open, from, to) {
        $row.find('.hours-open').prop('checked', open);
        if (from) { $row.find('.hours-from').val(from); }
        if (to) { $row.find('.hours-to').val(to); }
        refresh($row);
    }

    $box.on('change input focus', '.hours-row input', function () {
        var $row = $(this).closest('.hours-row');
        lastRow = $row.data('day');
        refresh($row);
    });

    $box.on('click', '.hours-office', function () {
        $box.find('.hours-row').each(function () {
            var day = $(this).data('day');
            setRow($(this), day < 5, '08:00', '18:00');
        });
    });

    $box.on('click', '.hours-copy', function () {
        var $src = $box.find('.hours-row[data-day="' + lastRow + '"]');
        var open = $src.find('.hours-open').is(':checked');
        var from = $src.find('.hours-from').val();
        var to = $src.find('.hours-to').val();
        $box.find('.hours-row').each(function () {
            setRow($(this), open, from, to);
        });
    });

    $box.on('click', '.hours-clear', function () {
        $box.find('.hours-row').each(function () {
            setRow($(this), false, '08:00', '18:00');
        });
    });

    $box.find('.hours-row').each(function () { refresh($(this)); });
})();
</script>
