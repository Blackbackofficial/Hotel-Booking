from uuid import UUID

import jwt
from circuitbreaker import circuit
from django.http import JsonResponse
from Rating_Service.settings import JWT_KEY
from django.shortcuts import render
from rest_framework import status
from rest_framework.decorators import api_view
from .serializers import HotelLikeSerializer, HotelSerializer, CommentSerializer, CommentLikeSerializer
from .models import LikeHotel, LikeComment, HotelLikes, CommentLikes

FAILURES = 3
TIMEOUT = 6

# Create your views here.

@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def create_hotel(request):
    """
    POST: {
          "hotel_uid": "b5f342ce-2419-4a17-8800-b921e90b5fbf"
          }
    """
    try:
        data = {"hotel_uid": request.data["hotel_uid"], "hotel_likes": "0", "hotel_dislikes": "0"}
        serializer = HotelSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        s = serializer.data
        return JsonResponse(serializer.data, status=status.HTTP_200_OK, safe=False)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def create_comment(request):
    """
    POST: {
          "hotel_uid": "zdr34673-2419-4a17-8800-b921e90b5fbf"
          "comment_text": "something"
          }
    """
    try:
        user = auth(request)
        data = {"hotel_uid": request.data["hotel_uid"],
                "user_uid": user["user_uid"], "comment_likes": "0", "comment_dislikes": "0"}
        serializer = CommentSerializer(data=data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return JsonResponse(serializer.data, status=status.HTTP_200_OK, safe=False)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['POST'])
def add_hotlike(request):
    try:
        user = auth(request)
        hotel_uid = request.data['hotel_uid']
        like_dis = request.data['like_dis']
        cur_hotel = HotelLikes.objects.get(hotel_uid=hotel_uid)
        try:
            LikeHotel.objects.get(user_uid=user['user_uid'], hotel_uid=hotel_uid,
                                  like=False, dislike=False).delete()
        except:
            pass
        try:
            hotellike = LikeHotel.objects.filter(user_uid=user['user_uid'], hotel_uid=hotel_uid).first()
            if like_dis == 'hotlike':
                if hotellike.like == False:
                    hotellike.like = True
                    hotellike.dislike = False
                else:
                    hotellike.like = False
            else:
                if hotellike.dislike == False:
                    hotellike.dislike = True
                    hotellike.like = False
                else:
                    hotellike.dislike = False
            hotellike.save()
            cur_hotel.hotel_likes = LikeHotel.objects.filter(hotel_uid=hotel_uid, like=True).count()
            cur_hotel.hotel_dislikes = LikeHotel.objects.filter(hotel_uid=hotel_uid, dislike=True).count()
            cur_hotel.save()
            return JsonResponse({'hotlikes': cur_hotel.hotel_likes, 'hotdislikes': cur_hotel.hotel_dislikes},
                                status=status.HTTP_200_OK, safe=False)
        except:
            if like_dis == 'hotlike':
                like = True
                dislike = False
            else:
                dislike = True
                like = False
            hotellike = LikeHotel(user_uid=user['user_uid'], hotel_uid=hotel_uid, like=like, dislike=dislike)
            hotellike.save()
            cur_hotel.hotel_likes = LikeHotel.objects.filter(hotel_uid=hotel_uid, like=True).count()
            cur_hotel.hotel_dislikes = LikeHotel.objects.filter(hotel_uid=hotel_uid, dislike=True).count()
            cur_hotel.save()
            return JsonResponse({'hotlikes': cur_hotel.hotel_likes, 'hotdislikes': cur_hotel.hotel_dislikes},
                                status=status.HTTP_200_OK, safe=False)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['PATCH'])
def add_comlike(request):
    try:
        user = auth(request)
        comment_uid = request.data['comment_uid']
        like_dis = request.data['like_dis']
        cur_comment = CommentLikes.objects.get(comment_uid=comment_uid)
        try:
            LikeComment.objects.get(user_uid=user['user_uid'], hotel_uid=comment_uid,
                                  like=False, dislike=False).delete()
        except:
            pass
        try:
            commentlike = LikeComment.objects.filter(user_uid=user['user_uid'], comment_uid=comment_uid).first()
            if like_dis == 'comlike':
                if commentlike.like == False:
                    commentlike.like = True
                    commentlike.dislike = False
                else:
                    commentlike.like = False
            else:
                if commentlike.dislike == False:
                    commentlike.dislike = True
                    commentlike.like = False
                else:
                    commentlike.dislike = False
            commentlike.save()
            cur_comment.hotel_likes = LikeComment.objects.filter(comment_uid=comment_uid,
                                                                 like=True).count()
            cur_comment.hotel_dislikes = LikeComment.objects.filter(comment_uid=comment_uid,
                                                                    dislike=True).count()
            cur_comment.save()
            return JsonResponse({'comlikes': cur_comment.comment_likes, 'comdislikes': cur_comment.comment_dislikes},
                                status=status.HTTP_200_OK, safe=False)
        except:
            if like_dis == 'comlike':
                like = True
                dislike = False
            else:
                dislike = True
                like = False
            commentlike = LikeComment(user_uid=user['user_uid'], comment_uid=comment_uid,
                                               like=like, dislike=dislike)
            commentlike.save()
            cur_comment.comment_likes = LikeComment.objects.filter(comment_uid=comment_uid, like=True).count()
            cur_comment.comment_dislikes = LikeComment.objects.filter(comment_uid=comment_uid, dislike=True).count()
            cur_comment.save()
            return JsonResponse({'comlikes': cur_comment.comment_likes, 'comdislikes': cur_comment.comment_dislikes},
                                status=status.HTTP_200_OK, safe=False)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def all_comments(request):
    try:
        comments = CommentLikes.objects.get(hotel_uid=request.data['hotel_uid']).all()
        return JsonResponse({'comments': comments}, status=status.HTTP_200_OK, safe=False)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_204_NO_CONTENT)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def show_hotlikes(request):
    try:
        try:
            user = auth(request)
            a = LikeHotel.objects.get(user_uid=user['user_uid'], hotel_uid=request.data['hotel_uid'])
            like = a.like
            dislike = a.dislike
        except:
            like = False
            dislike = False
        return JsonResponse({'like': like, 'dislike': dislike}, status=status.HTTP_200_OK, safe=False)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def show_comlikes(request):
    try:
        try:
            user = auth(request)
            a = LikeComment.objects.get(user_uid=user['user_uid'], comment_uid=request.data['comment_uid'])
            like = a.like
            dislike = a.dislike
        except:
            like = False
            dislike = False
        return JsonResponse({'like': like, 'dislike': dislike}, status=status.HTTP_200_OK, safe=False)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['DELETE'])
def delete_hotel(request):
    try:
        hotel = HotelLikes.objects.get(hotel_uid=request.data['hotel_uid'])
        hotel_likes = LikeHotel.objects.get(hotel_uid=request.data['hotel_uid']).all()
        hotel.delete()
        hotel_likes.delete()
        return JsonResponse({'detail': 'success deleted'}, status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['DELETE'])
def delete_comment(request):
    try:
        comment = CommentLikes.objects.get(comment_uid=request.data['hotel_uid']).all()
        for c in comment:
            comment_likes = LikeComment.objects.get(comment_uid=c.comment_uid).all()
            comment_likes.delete()
        comment.delete()
        return JsonResponse({'detail': 'success deleted'}, status=status.HTTP_204_NO_CONTENT)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def load_hotlikes(request):
    try:
        a = HotelLikes.objects.get(hotel_uid=request.data['hotel_uid'])
        return JsonResponse({'likes': a.hotel_likes, 'dislikes': a.hotel_dislikes}, status=status.HTTP_200_OK, safe=False)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


@circuit(failure_threshold=FAILURES, recovery_timeout=TIMEOUT)
@api_view(['GET'])
def load_comments(request):
    try:
        a = CommentLikes.objects.get(comment_uid=request.data['hotel_uid'])
        return JsonResponse({'comments': a}, status=status.HTTP_200_OK, safe=False)
    except Exception as e:
        return JsonResponse({'message': '{}'.format(e)}, status=status.HTTP_400_BAD_REQUEST)


def auth(request):
    token = request.COOKIES.get('jwt')

    if not token:
        return
    try:
        payload = jwt.decode(token, JWT_KEY, algorithms=['HS256'], options={"verify_exp": False})
    except jwt.DecodeError:
        return None
    payload.pop('exp')
    payload.pop('iat')
    return payload