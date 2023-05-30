$(document).ready(function(){
    $('.dropdown').hover(function() {
        $(this).find('.dropdown-menu').stop(true, true).delay(200).fadeIn(500);
    }, function() {
        $(this).find('.dropdown-menu').stop(true, true).delay(200).fadeOut(500);
    });

    $('#empresa').change(function() {
        updateObjectives();
    });

    $('#objetivo').change(function() {
        var objetivoId = $(this).val();
        $('#id_okr').val(objetivoId);
        updateKRs();
    });

    updateObjectives();
    updateKRs();

    $('.btn-approve').click(function(e) {
        if (!confirm('Tem certeza de que deseja aprovar esta macro ação? Ela será inserida no banco de dados.')) {
            e.preventDefault();
        }
    });

    $('.btn-reject').click(function(e) {
        if (!confirm('Tem certeza de que deseja recusar esta macro ação? Ela será excluída.')) {
            e.preventDefault();
        }
    });
});

function updateObjectives() {
    var objetivoOriginal = $('#objetivo').data('original');
    var empresaId = $('#empresa').val();

    $.getJSON('/get_okrs/' + empresaId, function(data) {
        var select = $('#objetivo');
        select.empty();
        data.forEach(function(okr) {
            var option = $('<option>');
            option.val(okr.id);
            option.text(okr.objetivo);
            if (okr.id == objetivoOriginal) {
                option.prop('selected', true);
            }
            select.append(option);
        });

        if (objetivoOriginal) {
            $('#id_okr').val(objetivoOriginal);
        } else {
            $('#id_okr').val($('#objetivo').val());
        }
    });

    $.getJSON('/get_empresa_info/' + empresaId, function(data) {
        $('#descricao_div').text(data.descricao_empresa);
        $('#cargos_div').text(data.usuarios.join(', '));
        $('#okrs_div').text(data.objetivos.join(', '));
        $('#krs_div').text(data.krs.join(', '));
        $('#macroacoes_div').text(data.macro_acoes.join(', '));
    });
}

function updateKRs() {
    var krOriginal = $('#kr').data('original');
    var objetivoId = $('#objetivo').val();

    $.getJSON('/get_krs/' + objetivoId, function(data) {
        var select = $('#kr');
        select.empty();
        data.forEach(function(kr) {
            var option = $('<option>');
            option.val(kr.id);  // Define o valor da opção para o ID do KR
            option.text(kr.texto);
            if (kr.id == krOriginal) {
                option.prop('selected', true);
            }
            select.append(option);
        });
    });
}
