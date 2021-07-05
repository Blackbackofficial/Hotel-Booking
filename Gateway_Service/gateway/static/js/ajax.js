function del_booking(){
    var data = confirm("Are you sure you want to cancel your reservation?");
}
$(document).ready(function(){
    $.each($('.hotlikes-button'), function(){
        var hotel = $(this).attr("data-ans");
        var $like1 = $('#likehot' + hotel);
        var $dis1 = $('#dishot' + hotel);
        $.post('/show_hotlikes', {hotel_uid: hotel}, function(data) {
            if(data.like === true){
                $like1.css('color', 'rgb(102, 51, 153)');
            }else if(data.dislike === true){
                $dis1.css('color', 'rgb(102, 51, 153)');
            }
        });
    });
    $.each($('.comlikes-button'), function(){
        var comment = $(this).attr("data-ans");
        var $like = $('#likecom' + comment);
        var $dis = $('#discom' + comment);
        $.post('/show_comlikes', {comment_uid: comment}, function(data) {
            if(data.like === true){
                $like.css('color', 'rgb(102, 51, 153)');
            }else if(data.dislike === true){
                $dis.css('color', 'rgb(102, 51, 153)');
            }
        });
    });
});

$('.hotlikes-button').click(function(){
    var hotel = $(this).attr("data-ans");
    var answer = $(this).attr("answer");
    var $like = $('#likehot' + hotel);
    var $dis = $('#dishot' + hotel);
    var cur = parseInt($like.text());
    var cur2 = parseInt($dis.text());
    if(answer === "hotlike"){
        if($like.css('color') === 'rgb(255, 255, 255)'){
            cur++;
            $like.text(cur);
            $like.css('color', 'rgb(102, 51, 153)');
            $dis.css('color', 'rgb(255, 255, 255)');
        }else{
            cur--;
            $like.text(cur);
            $like.css('color', 'rgb(255, 255, 255)');
        };
    }else{
        if($dis.css('color') === "rgb(255, 255, 255)"){
            cur2++;
            $dis.text(cur2);
            $dis.css('color', 'rgb(102, 51, 153)');
            $like.css('color', 'rgb(255, 255, 255)');
        }else{
            cur2--;
            $dis.text(cur2);
            $dis.css('color', 'rgb(255, 255, 255)');
        };
    };
    $.post('/add_hotlike', {hotel_uid: hotel, answer: answer}, function(data) {
        $('#likehot' + hotel).text(data.hotlikes);
        $('#dishot' + hotel).text(data.hotdislikes);
    });
});

$('.comlikes-button').click(function(){
    var comment = $(this).attr("data-ans");
    var answer = $(this).attr("answer");
    var $like = $('#likecom' + comment);
    var $dis = $('#discom' + comment);
    var cur = parseInt($like.text());
    var cur2 = parseInt($dis.text());
    if(answer === "comlike"){
        if($like.css('color') === 'rgb(255, 255, 255)'){
            cur++;
            $like.text(cur);
            $like.css('color', 'rgb(102, 51, 153)');
            $dis.css('color', 'rgb(255, 255, 255)');
        }else{
            cur--;
            $like.text(cur);
            $like.css('color', 'rgb(255, 255, 255)');
        };
    }else{
        if($dis.css('color') === "rgb(255, 255, 255)"){
            cur2++;
            $dis.text(cur2);
            $dis.css('color', 'rgb(102, 51, 153)');
            $like.css('color', 'rgb(255, 255, 255)');
        }else{
            cur2--;
            $dis.text(cur2);
            $dis.css('color', 'rgb(255, 255, 255)');
        };
    };
    $.post('/add_comlike', {comment_uid: comment, answer: answer}, function(data) {
        $('#likecom' + comment).text(data.comlikes);
        $('#discom' + comment).text(data.comdislikes);
    });
});


$('.comment_update').click(function(){
    var ans = $(this).attr("data-ans");
    $.ajax({
        type: 'GET',
        cache: 'false',
        url: '/' + ans + '/update_comment',
        success: function (result) {
            $('#curcom' + ans).replaceWith(result);
            },
    });
});

$('.comment_delete').click(function(){
    var dat = confirm('Are you sure you want to delete comment?');
    var comment = $(this).attr("data-ans");
    if(dat){
        $.post('/delete_comment',{comment_uid: comment}, function(data) {
            console.log(data);
            if (data.commessage === 'success deleted'){
                alert('Comment deleted');
                location.reload();
            }
            else {
                alert('Deletion error');
            }
        });
    }
});