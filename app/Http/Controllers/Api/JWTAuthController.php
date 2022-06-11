<?php

namespace App\Http\Controllers\API;

use JWTAuth;
use Validator;
use App\Models\User;
use Illuminate\Http\Request;
use Tymon\JWTAuth\Exceptions\JWTException;
use Symfony\Component\HttpFoundation\Response;
use App\Http\Controllers\Controller;

class JwtAuthController extends Controller
{
    public $token = true;

    public function register(Request $request)
    {

        $validator = Validator::make(
            $request->all(),
            [
                'name' => 'required',
                'email' => 'required|email',
                'password' => 'required',
                'c_password' => 'required|same:password',
            ]
        );

        if ($validator->fails()) {

            return response()->json(['error' => $validator->errors()], 401);
        }


        $user = new User;
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = bcrypt($request->password);
        $user->save();

        // if ($this->token) {
        //     return $this->login($request);
        // }

        return response()->json([
            'success' => true,
            'data' => $user
        ], Response::HTTP_OK);
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);

        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }

        if (!$token = auth()->attempt($validator->validated())) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }

        return $this->respondWithToken($token);

        // return response()->json([
        //     'success' => true,
        //     'token' => $jwt_token,
        // ]);
    }

    public function logout(Request $request)
    {

        $validator = Validator::make(
            array(
                'token' => $request->input('token'),
            ),
            array(
                'token' => 'required',
            )
        );
        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => $validator->fails(),
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
        

        try {
            JWTAuth::invalidate($request->token);

            return response()->json([
                'success' => true,
                'message' => 'User logged out successfully'
            ]);
        } catch (JWTException $exception) {
            return response()->json([
                'success' => false,
                'message' => 'Sorry, the user cannot be logged out'
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    public function getUser(Request $request)
    {
        $validator = Validator::make(
            array(
                'token' => $request->input('token'),
            ),
            array(
                'token' => 'required',
            )
        );
        if ($validator->fails()) {
            return response()->json([
                'success' => false,
                'message' => $validator->fails(),
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }

        $user = JWTAuth::authenticate($request->token);

        return response()->json(['user' => $user]);
    }
}
